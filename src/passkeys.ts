// src/passkeys.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import * as jose from "jose";

const u8 = (s: string) => new TextEncoder().encode(s);

const cors = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
};

const b64url = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  // @ts-ignore Buffer via nodejs_compat
  return Buffer.from(bytes).toString("base64url");
};
const b64urlToBuf = (s: string) => {
  // @ts-ignore Buffer via nodejs_compat
  return Buffer.from(s, "base64url");
};

async function getUserByUsername(DB: D1Database, email: string) {
  return DB.prepare("SELECT * FROM user WHERE email = ?")?.bind(email).first<any>();
}

async function getCredsByUser(DB: D1Database, userId: string) {
  const rs = await DB.prepare("SELECT * FROM credentials WHERE user_id = ?")?.bind(userId).all<any>();
  return rs.results ?? [];
}

export const routes = {
  async registerOptions(req: Request, env: Env) {
    const {email} = await req.json<any>();
    let user = await getUserByUsername(env.AUTH_DB, email);
    if (!user) {
      const id = crypto.randomUUID();
      await env.AUTH_DB.prepare("INSERT INTO user (id, email, created_at) VALUES (?, ?, ?)")
        .bind(id, email, Date.now()).run();
      user = {id, email};
    }
    const excludeCredentials = (await getCredsByUser(env.AUTH_DB, user.id)).map((c: any) => ({
      id: c.id, type: "public-key" as const
    }));

    const opts = await generateRegistrationOptions({
      rpID: env.RP_ID,
      rpName: env.RP_NAME,
      userName: user.email,
      userID: u8(user.id),
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {residentKey: "preferred", userVerification: "preferred"},
    });

    await env.AUTH_STORAGE.put(`reg-chal:${user.id}`, opts.challenge, {expirationTtl: 300});
    return new Response(JSON.stringify(opts), {headers: {...cors, "content-type": "application/json"}});
  },

  async registerVerify(req: Request, env: Env) {
    const {email, attResp} = await req.json<any>();
    const user = await getUserByUsername(env.AUTH_DB, email);
    if (!user) return new Response(JSON.stringify({error: "user not found"}), {status: 404, headers: cors});

    const challenge = await env.AUTH_STORAGE.get(`reg-chal:${user.id}`);
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: challenge!,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
    });
    if (!verification.verified || !verification.registrationInfo)
      return new Response(JSON.stringify({verified: false}), {status: 400, headers: cors});

    try {

      const {fmt, aaguid, credentialBackedUp, credentialDeviceType, credential, attestationObject} =
        verification.registrationInfo;

      await env.AUTH_DB.prepare(
        `INSERT INTO credentials (id, user_id, public_key, counter, fmt, aaguid, backed_up, uv, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        b64url(attestationObject),
        user.id,
        credential.publicKey,
        credential.counter,
        fmt,
        aaguid,
        credentialBackedUp ? 1 : 0,
        credentialDeviceType === "multiDevice" ? 1 : 0,
        Date.now()
      ).run();
    } catch (e) {
      return new Response(JSON.stringify({verified: false, error: JSON.stringify(e)}), {status: 400, headers: cors});
    }

    return new Response(JSON.stringify({verified: true}), {headers: cors});
  },

  async loginOptions(req: Request, env: Env) {
    const {email} = await req.json<any>();
    const user = await getUserByUsername(env.AUTH_DB, email);
    if (!user) return new Response(JSON.stringify({verified: false, error: "user not found"}), {status: 404, headers: cors});

    const opts = await generateAuthenticationOptions({
      rpID: env.RP_ID,
    });

    await env.AUTH_STORAGE.put(`auth-chal:${user.id}`, opts.challenge, {expirationTtl: 300});
    return new Response(JSON.stringify({...opts, userID: user.id}), {
      headers: {
        ...cors,
        "content-type": "application/json"
      }
    });
  },

  async loginVerify(req: Request, env: Env) {
    const {userID, credResp} = await req.json<any>();
    const creds = await getCredsByUser(env.AUTH_DB, userID);
    const challenge = await env.AUTH_STORAGE.get(`auth-chal:${userID}`);

    const dbCred =
      creds.find((c: any) => c.id === credResp.id) ||
      creds.find((c: any) => b64urlToBuf(c.id).byteLength === b64urlToBuf(credResp.id).byteLength) ||
      creds[0];

    if (!dbCred) return new Response(JSON.stringify({error: "no creds"}), {status: 400, headers: cors});

    const verification = await verifyAuthenticationResponse({
      response: credResp,
      expectedChallenge: challenge!,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      credential: {
        id: dbCred.id,
        publicKey: dbCred.public_key,
        counter: dbCred.counter,
      },
    });
    if (!verification.verified || !verification.authenticationInfo)
      return new Response(JSON.stringify({verified: false}), {status: 401, headers: cors});

    await env.AUTH_DB.prepare("UPDATE credentials SET counter=? WHERE id=?")
      .bind(verification.authenticationInfo.newCounter, dbCred.id).run();

    const jwt = await new jose.SignJWT({sub: userID}).setIssuedAt()
      .setExpirationTime("1h").setProtectedHeader({alg: "HS256"})
      .sign(new TextEncoder().encode(env.SESSION_SECRET));

    return new Response(JSON.stringify({verified: true}), {
      headers: {
        ...cors,
        "content-type": "application/json",
        "set-cookie": `sid=${jwt}; Secure; HttpOnly; SameSite=Lax; Path=/`,
      }
    });
  },
};
