import {routes} from "./passkeys";
import * as jose from "jose";

const AASA = {
  applinks: {
    apps: [],
    details: [{appID: "884JRH5R93.com.bitpay.wallet", paths: ["/i/*", "/wallet/wc", "/uni/*", "/f/uni/*"]}]
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

const u8 = (s: string) => new TextEncoder().encode(s);
const json = (d: unknown, s = 200, h: Record<string, string> = {}) =>
  new Response(JSON.stringify(d), {status: s, headers: {"content-type": "application/json", ...cors, ...h}});

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
  uv: boolean;
  created_at?: number;
};

type MeResponse = {
  email: string;
  credentials: Array<CredentialRow>;
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, {
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type"
      }
    });

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

    // GET /debug/creds?email=foo
    if (url.pathname === "/debug/creds") {
      const email = url.searchParams.get("email")!;
      const user = await env.AUTH_DB.prepare("SELECT * FROM user WHERE email=?").bind(email).first<any>();
      if (!user) return json({user: null, credentials: []});
      const creds = await env.AUTH_DB.prepare("SELECT * FROM credentials WHERE user_id=?").bind(user.id).all<any>();
      return json({user, credentials: creds.results ?? []});
    }

    if (url.pathname === "/") {
      const html = await env.ASSETS.fetch(new Request(new URL("/index.html", request.url)));
      return new Response(await html.text(), {headers: {"content-type": "text/html"}});
    }

    if (url.pathname === "/webauthn/register/options" && request.method === "POST") return routes.registerOptions(request, env);
    if (url.pathname === "/webauthn/register/verify" && request.method === "POST") return routes.registerVerify(request, env);
    if (url.pathname === "/webauthn/login/options" && request.method === "POST") return routes.loginOptions(request, env);
    if (url.pathname === "/webauthn/login/verify" && request.method === "POST") return routes.loginVerify(request, env);

    // --- API: JSON for the page ---
    if (request.method === 'GET' && url.pathname === '/me.json') {
      return handleGetMe(request, env);
    }

    const delMatch = url.pathname.match(/^\/webauthn\/credentials\/([^/]+)$/);
    if (request.method === 'DELETE' && delMatch) {
      const credId = decodeURIComponent(delMatch[1]);
      return handleDeleteCredential(request, env, credId);
    }

    if (request.method === 'GET' && url.pathname === "/me") {
      const html = await env.ASSETS.fetch(new Request(new URL("/me-page.html", request.url)));
      const cookie = request.headers.get("cookie") || "";
      const sid = /(?:^|;\s*)sid=([^;]+)/.exec(cookie)?.[1];
      if (!sid) return json({ok: false}, 401);
      try {
        await jose.jwtVerify(sid, u8(env.SESSION_SECRET));
        //return json({ok: true});
        return new Response(await html.text(), {headers: {"content-type": "text/html"}});
      } catch {
        return json({ok: false}, 401);
      }
    }

    // Fallthrough: let static assets handle it
    return new Response("Not found", {status: 404, headers: cors});
  },
} satisfies ExportedHandler<Env>;

async function handleGetMe(request: Request, env: Env): Promise<Response> {
  const user = await getUserFromSession(request, env);
  if (!user) return jsonData({error: 'Unauthorized'}, 401);

  const email = user.email as string;

  const credsRes = await env.AUTH_DB.prepare(
    `SELECT id,
            user_id,
            public_key,
            counter,
            fmt,
            aaguid,
            backed_up,
            uv,
            created_at
     FROM credentials
     WHERE user_id = ?
     ORDER BY created_at ASC`
  ).bind(user.id).all<CredentialRow>();

  const credentials = (credsRes.results || []).map((r) => ({
    id: r.id,
    user_id: r.user_id,
    public_key: r.public_key,
    counter: r.counter,
    fmt: r.fmt,
    aaguid: r.aaguid,
    backed_up: r.backed_up,
    uv: r.uv,
    created_at: r.created_at,
  }));

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
              JOIN users u ON u.id = s.user_id
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

function safeParseArray(s: string): string[] {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
