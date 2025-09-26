import {routes} from "./passkeys";

const PATH_API = '/passkey';
const PATH_REGISTER_CHALLENGE = PATH_API + '/register/challenge';
const PATH_REGISTER_VERIFY = PATH_API + '/register/verify';
const PATH_AUTH_CHALLENGE = PATH_API + '/authenticate/challenge';
const PATH_AUTH_VERIFY = PATH_API + '/authenticate/verify';
const PATH_STATUS = PATH_API + '/status';
const PATH_CREDENTIALS = PATH_API + '/credentials';
const PATH_BOOTSTRAP = PATH_API + '/bootstrap';
const PATH_HEALTH = PATH_API + '/health';

const AASA = {
  applinks: {
    apps: [],
    details: [{appID: "884JRH5R93.com.bitpay.wallet", paths: ["/i/*", "/wallet/wc", "/uni/*", "/f/uni/*"]}]
  },
  webcredentials: {
    apps: ["884JRH5R93.com.bitpay.wallet"]
  }
};

const ASSETLINKS = [
  {
    relation: [
      "delegate_permission/common.get_login_creds",
      "delegate_permission/common.handle_all_urls",
    ],
    target: {
      namespace: "android_app",
      package_name: "com.bitpay.wallet",
      sha256_cert_fingerprints: [
        "BA:F3:3F:AB:18:62:54:29:96:45:99:81:17:75:45:8B:53:12:44:EF:A9:3A:DD:23:5D:69:E1:9A:05:43:43:CD",
      ],
    },
  },
];

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "public, max-age=3600",
  "x-content-type-options": "nosniff",
};

const cors = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
};

type CredentialRow = {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  fmt: string;
  aaguid: string;
  backed_up: boolean;
  multi_device: boolean;
  created_at: number;
};

type MeResponse = {
  email: string;
  credentials: Array<CredentialRow>;
};

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, {
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type"
      }
    });

    // ---- XHR logout (fetch from JS)
    if (request.method === 'POST' && url.pathname === '/logout') {
      return handleLogout(request, env, /*mode=*/'api');
    }

    // ---- Link/logout via URL (navigation)
    if (request.method === 'GET' && url.pathname === '/logout') {
      return handleLogout(request, env, /*mode=*/'nav');
    }

    if (
      url.pathname === "/.well-known/apple-app-site-association" ||
      url.pathname === "/apple-app-site-association"
    ) {
      return new Response(JSON.stringify(AASA), {headers: JSON_HEADERS});
    }

    if (
      url.pathname === "/.well-known/assetlinks.json" ||
      url.pathname === "/assetlinks.json"
    ) {
      return new Response(JSON.stringify(ASSETLINKS), {headers: JSON_HEADERS});
    }

    if (request.method === 'GET' && url.pathname === PATH_CREDENTIALS) {
      const hasEmail = url.searchParams.has('email');
      if (hasEmail) {
        const email = url.searchParams.get('email')!;
        const user = await env.AUTH_DB.prepare('SELECT id FROM user WHERE email = ?').bind(email).first<{ id: string }>();
        if (!user) {
          return jsonData({passkey: false}, 200);
        }
        const exists = await checkIfCredentialsExist(env, user.id);
        if (!exists) {
          return jsonData({passkey: false}, 200);
        }
        const credentials = await getCredentialFromDb(user.id, env);

        const body: MeResponse = {email, credentials};
        return jsonData(body, 200);

      }
      return handleGetMe(request, env);
    }

    // Check if credentials exist by email or username
    if (request.method === 'GET' && url.pathname === PATH_STATUS && url.searchParams.has('email')) {
      const email = url.searchParams.get('email')!;
      const user = await env.AUTH_DB.prepare('SELECT id FROM user WHERE email = ?').bind(email).first<{ id: string }>();
      if (!user) {
        return jsonData({passkey: false}, 200);
      }
      const exists = await checkIfCredentialsExist(env, user.id);
      return jsonData({passkey: exists}, 200);
    }

    if (url.pathname === "/") {
      const html = await env.ASSETS.fetch(new Request(new URL("/index.html", request.url)));
      return new Response(await html.text(), {headers: {"content-type": "text/html"}});
    }

    if (url.pathname === PATH_REGISTER_CHALLENGE && request.method === "POST") return routes.registerOptions(request, env);
    if (url.pathname === PATH_REGISTER_VERIFY && request.method === "POST") return routes.registerVerify(request, env);
    if (url.pathname === PATH_AUTH_CHALLENGE && request.method === "POST") return routes.loginOptions(request, env);
    if (url.pathname === PATH_AUTH_VERIFY && request.method === "POST") return routes.loginVerify(request, env);

    const delMatch = url.pathname.match(/^\/passkey\/credentials\/([^/]+)$/);
    if (request.method === 'DELETE' && delMatch) {
      const credId = decodeURIComponent(delMatch[1]);
      return handleDeleteCredential(request, env, credId);
    }

    if (request.method === 'GET' && url.pathname === "/me") {
      try {
        const html = await env.ASSETS.fetch(new Request(new URL("/me-page.html", request.url)));
        const user = await getUserFromSession(request, env);
        if (!user) return jsonData({error: 'Unauthorized'}, 401);
        return new Response(await html.text(), {headers: {"content-type": "text/html"}});
      } catch (e) {
        return  jsonData({error: e, verified: false}, 401);
      }
    }

    // 1) Bootstrap: create or fetch user by email and issue session
    if (url.pathname === PATH_BOOTSTRAP && request.method === "POST") {
      const { email } = await request.json<any>();
      if (!email || typeof email !== "string") {
        return new Response(JSON.stringify({error: "Email required"}), {status: 400, headers: cors});
      }

      const userId = await upsertUserByEmail(env.AUTH_DB, email);
      const sid = await createSession(env.AUTH_DB, userId, 60 * 60 * 24 * 7); // 7 days
      const jwt = await signJWT({ sub: userId, sid }, env.SESSION_SECRET, { expSeconds: 60 * 60 * 24 * 7 });

      const headers = new Headers({ "content-type": "application/json" });
      headers.append("set-cookie", sessionCookie(jwt, env.ORIGIN, 60 * 60 * 24 * 7));
      return new Response(JSON.stringify({ token: jwt, userId }), { status: 200, headers });
    }

    // Fallthrough: let static assets handle it
    return new Response("Not found", {status: 404, headers: cors});
  },
} satisfies ExportedHandler<Env>;

async function getCredentialFromDb(user_id: string, env: Env): Promise<Array<CredentialRow>> {
  const credsRes = await env.AUTH_DB.prepare(
    `SELECT id,
            user_id,
            public_key,
            counter,
            fmt,
            aaguid,
            backed_up,
            multi_device,
            created_at
     FROM credentials
     WHERE user_id = ?
     ORDER BY created_at ASC`
  ).bind(user_id).all<CredentialRow>();

  return (credsRes.results || []).map((r) => ({
    id: r.id,
    user_id: r.user_id,
    public_key: r.public_key,
    counter: r.counter,
    fmt: r.fmt,
    aaguid: r.aaguid,
    backed_up: r.backed_up,
    multi_device: r.multi_device,
    created_at: r.created_at,
  }));
}

async function handleGetMe(request: Request, env: Env): Promise<Response> {
  const user = await getUserFromSession(request, env);
  if (!user) return jsonData({error: 'Unauthorized'}, 401);

  const email = user.email as string;

  const credentials = await getCredentialFromDb(user.id, env);

  const body: MeResponse = {email, credentials};
  return jsonData(body, 200);
}

async function handleDeleteCredential(request: Request, env: Env, credentialId: string): Promise<Response> {
  const user = await getUserFromSession(request, env);
  if (!user) return jsonData({error: 'Unauthorized'}, 401);

  const countRes = await env.AUTH_DB
    .prepare(`SELECT COUNT(*) as n
              FROM credentials
              WHERE user_id = ?`)
    .bind(user.id).first<{ n: number }>();
  const total = Number(countRes?.n ?? 0);
  if (total <= 1) {
    return jsonData({error: 'You must keep at least one passkey.'}, 409);
  }

  const del = await env.AUTH_DB
    .prepare(`DELETE
              FROM credentials
              WHERE id = ?
                AND user_id = ?`)
    .bind(credentialId, user.id)
    .run();

  if ((del.meta as any)?.changes === 0) {
    return jsonData({error: 'Not found'}, 404);
  }

  return new Response(null, {status: 204});
}

async function checkIfCredentialsExist(env: Env, userId: string): Promise<boolean> {
  const countRes = await env.AUTH_DB
    .prepare(`SELECT COUNT(*) as n
              FROM credentials
              WHERE user_id = ?`)
    .bind(userId).first<{ n: number }>();
  const total = Number(countRes?.n ?? 0);
  return total > 0;
}

/* ---------------- helpers ---------------- */

function jsonData(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {'content-type': 'application/json; charset=utf-8'},
  });
}

// Very basic cookie parsing (adjust if you already use a lib)
function getCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return null;
  const m = cookie.match(new RegExp(`(?:^|; )${escapeRe(name)}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function getUserFromSession(request: Request, env: Env): Promise<{ id: string; email: string } | null> {
  const sid = getCookie(request, 'sid');
  if (!sid) return null;

  // Validate session & not expired
  const row = await env.AUTH_DB
    .prepare(
      `SELECT u.id as user_id, u.email as email, s.expires_at
       FROM sessions s
              JOIN user u ON u.id = s.user_id
       WHERE s.sid = ?`
    )
    .bind(sid)
    .first<{ user_id: string; email: string; expires_at: number }>();

  if (!row) return null;
  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at <= now) {
    await env.AUTH_DB.prepare(`DELETE
                               FROM sessions
                               WHERE sid = ?`).bind(sid).run();
    return null;
  }
  return {id: row.user_id, email: row.email};
}

async function handleLogout(request: Request, env: Env, mode: 'api' | 'nav') {
  const sid = getCookie(request, 'sid');

  if (sid && env.AUTH_DB) {
    try {
      await env.AUTH_DB.prepare('DELETE FROM sessions WHERE sid = ?').bind(sid).run();
    } catch { /* ignore */
    }
  }

  const headers = new Headers();
  headers.set('Set-Cookie', clearSidCookie()); // remove cookie

  if (mode === 'nav') {
    headers.set('Location', '/');
    return new Response(null, {status: 303, headers});
  } else {
    // API mode for fetch('/logout', { method: 'POST' })
    return new Response(null, {status: 204, headers});
  }
}

function clearSidCookie(): string {
  // No Domain attribute -> clears cookie for current host only
  return [
    'sid=',
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ].join('; ');
}

async function upsertUserByEmail(db: D1Database, email: string) {
  const existing = await db.prepare("SELECT id FROM user WHERE email = ?").bind(email).first<{id:string}>();
  if (existing?.id) return existing.id;
  const id = crypto.randomUUID();
  await db.prepare("INSERT INTO user (id, email, created_at) VALUES (?, ?, ?)")
    .bind(id, email.toLowerCase(), Date.now()).run();
  return id;
}

async function createSession(db: D1Database, userId: string, ttlSec: number) {
  const sid = crypto.randomUUID();
  const now = Date.now();
  await db.prepare(
    "INSERT INTO sessions (sid, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(sid, userId, now + ttlSec * 1000).run();
  return sid;
}

const b64url = (buf: ArrayBuffer | Uint8Array) => {
  let str = typeof buf === "string" ? buf : btoa(String.fromCharCode(...new Uint8Array(buf)));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const b64urlDecode = (str: string) =>
  Uint8Array.from(atob(str.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

async function hmacSHA256(secret: string, data: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}

function sessionCookie(token: string, origin: string, maxAgeSec: number) {
  const url = new URL(origin);
  const domain = url.hostname; // tweak if you need a parent domain
  return [
    `session=${encodeURIComponent(token)}`,
    `Path=/`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Lax`,
    `Max-Age=${maxAgeSec}`,
    `Domain=${domain}`,
  ].join("; ");
}

async function signJWT(payload: Record<string, any>, secret: string, { expSeconds = 3600 } = {}) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + expSeconds, ...payload };

  const h = b64url(new TextEncoder().encode(JSON.stringify(header)));
  const p = b64url(new TextEncoder().encode(JSON.stringify(body)));
  const sig = b64url(await hmacSHA256(secret, `${h}.${p}`));
  return `${h}.${p}.${sig}`;
}
