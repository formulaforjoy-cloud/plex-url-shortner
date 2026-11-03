
const COOKIE = "plex_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });
}

function html(text, status = 200) {
  return new Response(text, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function b64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) {
    s += String.fromCharCode(b);
  }
  return btoa(s)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/,"");
}

function unb64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function digest(value) {
  const data = new TextEncoder().encode(value);
  return b64(await crypto.subtle.digest("SHA-256", data));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(value)
    )
  );
}

async function verifyPassword(password, stored) {
  const [salt, expected] = (stored || "").split("$");
  if (!salt || !expected) return false;
  return (await digest(salt + password)) === expected;
}

async function passwordHash(password) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(18)));
  return salt + "$" + await digest(salt + password);
}

function cookieValue(request) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : "";
}

async function isAuthed(request, env) {
  const token = cookieValue(request);
  if (!token || !env.SESSION_SECRET) return false;

  const [payload, sig] = token.split(".");
  if (!payload || !sig ||
      await sign(payload, env.SESSION_SECRET) !== sig) {
    return false;
  }

  try {
    const obj = JSON.parse(
      new TextDecoder().decode(unb64(payload))
    );
    return obj.exp > Date.now() / 1000;
  } catch {
    return false;
  }
}

function sessionCookie(token) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;
}

async function makeSession(env) {
  const payload = b64(
    new TextEncoder().encode(
      JSON.stringify({
        exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
        nonce: crypto.randomUUID()
      })
    )
  );

  return payload + "." + await sign(payload, env.SESSION_SECRET);
}

function validSlug(slug) {
  return /^[a-z0-9][a-z0-9_-]{1,48}[a-z0-9]$/.test(slug);
}

function validUrl(value) {
  try {
    const u = new URL(value);
    return ["http:", "https:"].includes(u.protocol) && !!u.hostname;
  } catch {
    return false;
  }
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function requireAuth(request, env) {
  if (!(await isAuthed(request, env))) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null;
}

async function api(request, env, url) {
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/setup-status") {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='password_hash'"
    ).first();

    return json({ setup: !!row });
  }

  if (request.method === "POST" && path === "/api/setup") {
    const existing = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='password_hash'"
    ).first();

    if (existing) {
      return json({ error: "Setup already completed" }, 409);
    }

    const data = await body(request);

    if (typeof data.password !== "string" ||
        data.password.length < 12) {
      return json({
        error: "Use a password with at least 12 characters"
      }, 400);
    }

    await env.DB.prepare(
      "INSERT INTO settings(key,value) VALUES('password_hash',?)"
    ).bind(await passwordHash(data.password)).run();

    const token = await makeSession(env);

    return json({ ok: true }, 200, {
      "set-cookie": sessionCookie(token)
    });
  }

  if (request.method === "POST" && path === "/api/login") {
    const data = await body(request);

    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key='password_hash'"
    ).first();

    if (!row ||
        !(await verifyPassword(String(data.password || ""), row.value))) {
      return json({ error: "Incorrect password" }, 401);
    }

    const token = await makeSession(env);

    return json({ ok: true }, 200, {
      "set-cookie": sessionCookie(token)
    });
  }

  if (request.method === "POST" && path === "/api/logout") {
    return json({ ok: true }, 200, {
      "set-cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
    });
  }

  const denied = await requireAuth(request, env);
  if (denied) return denied;

  if (request.method === "GET" && path === "/api/links") {
    const { results = [] } = await env.DB.prepare(
      "SELECT id,slug,destination,title,active,clicks,created_at,updated_at FROM links ORDER BY created_at DESC"
    ).all();

    const totals = await env.DB.prepare(
      "SELECT COUNT(*) total, SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) active, COALESCE(SUM(clicks),0) clicks FROM links"
    ).first();

    return json({ links: results, totals });
  }

  if (request.method === "POST" && path === "/api/links") {
    const data = await body(request);
    const slug = String(data.slug || "").trim().toLowerCase();
    const destination = String(data.destination || "").trim();
    const title = String(data.title || "").trim().slice(0, 100);

    if (!validSlug(slug)) {
      return json({
        error: "Slug must be 3–50 characters: lowercase letters, numbers, hyphens or underscores"
      }, 400);
    }

    if (!validUrl(destination)) {
      return json({ error: "Enter a valid http or https URL" }, 400);
    }

    try {
      await env.DB.prepare(
        "INSERT INTO links(id,slug,destination,title) VALUES(?,?,?,?)"
      ).bind(crypto.randomUUID(), slug, destination, title).run();

      return json({ ok: true }, 201);
    } catch {
      return json({ error: "That short slug is already in use" }, 409);
    }
  }

  const match = path.match(/^\/api\/links\/([a-f0-9-]+)$/);

  if (match && request.method === "PUT") {
    const data = await body(request);
    const id = match[1];
    const destination = String(data.destination || "").trim();
    const title = String(data.title || "").trim().slice(0, 100);

    if (!validUrl(destination)) {
      return json({ error: "Enter a valid http or https URL" }, 400);
    }

    await env.DB.prepare(
      "UPDATE links SET destination=?,title=?,updated_at=datetime('now') WHERE id=?"
    ).bind(destination, title, id).run();

    return json({ ok: true });
  }

  if (match && request.method === "PATCH") {
    const data = await body(request);

    await env.DB.prepare(
      "UPDATE links SET active=?,updated_at=datetime('now') WHERE id=?"
    ).bind(data.active ? 1 : 0, match[1]).run();

    return json({ ok: true });
  }

  if (match && request.method === "DELETE") {
    await env.DB.prepare(
      "DELETE FROM links WHERE id=?"
    ).bind(match[1]).run();

    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env, url);
      } catch (e) {
        return json({ error: "Server error" }, 500);
      }
    }

    if (request.method === "GET" &&
        url.pathname !== "/" &&
        !url.pathname.includes(".")) {

      const slug = decodeURIComponent(url.pathname.slice(1));

      const row = await env.DB.prepare(
        "SELECT destination,active FROM links WHERE slug=?"
      ).bind(slug).first();

      if (!row) {
        return html(
          "<!doctype html><title>Link not found</title><main style='font:16px system-ui;text-align:center;padding:12vh 20px'><h1>Link not found</h1><p>This Plex short link does not exist.</p></main>",
          404
        );
      }

      if (!row.active) {
        return html(
          "<!doctype html><title>Link disabled</title><main style='font:16px system-ui;text-align:center;padding:12vh 20px'><h1>Link unavailable</h1><p>This short link has been deactivated.</p></main>",
          410
        );
      }

      await env.DB.prepare(
        "UPDATE links SET clicks=clicks+1 WHERE slug=?"
      ).bind(slug).run();

      return Response.redirect(row.destination, 302);
    }

    return env.ASSETS.fetch(request);
  }
};
