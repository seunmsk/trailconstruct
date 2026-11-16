// TrailConstruct API — Cloudflare Pages Functions + D1 (database) + R2 (photos).
// Every request is checked against the user's role on that project.

const COLS = ["projects", "logs", "reports", "updates", "expenses", "requests", "matreqs", "stock", "milestones"];
const READ = {
  developer: COLS,
  engineer: ["projects", "logs", "reports", "matreqs", "stock"],
  investor: ["projects", "updates", "milestones", "requests"],
};
const WRITE = {
  developer: COLS,
  engineer: ["projects", "logs", "reports", "matreqs", "stock"],
  investor: ["requests", "milestones"],
};
const ROLES = ["developer", "engineer", "investor"];
const ID_RE = /^[A-Za-z0-9_\-:.]{1,80}$/;
const MAX_DOC = 200 * 1024;
const MAX_PHOTO = 12 * 1024 * 1024;
const SESSION_DAYS = 30;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
const err = (status, message) => json({ error: message }, status);

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const randCode = (n = 10) => {
  const a = "abcdefghjkmnpqrstuvwxyz23456789", r = crypto.getRandomValues(new Uint8Array(n));
  return [...r].map((x) => a[x % a.length]).join("");
};

async function hashPassword(password, saltHex, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return hex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function cookie(req, name) {
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
const sessionCookie = (token, maxAge) =>
  `st_s=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

async function currentUser(req, env) {
  const t = cookie(req, "st_s");
  if (!t || !/^[a-f0-9]{64}$/.test(t)) return null;
  return env.DB.prepare(
    "SELECT u.id, u.name, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?"
  ).bind(t, Date.now()).first();
}
async function startSession(env, userId) {
  const token = randHex(32);
  await env.DB.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(token, userId, Date.now() + SESSION_DAYS * 864e5).run();
  return sessionCookie(token, SESSION_DAYS * 86400);
}
async function roleOn(env, userId, pid) {
  const r = await env.DB.prepare("SELECT role FROM members WHERE project_id = ? AND user_id = ?").bind(pid, userId).first();
  return r ? r.role : null;
}
async function memberships(env, userId) {
  const r = await env.DB.prepare("SELECT project_id AS pid, role FROM members WHERE user_id = ?").bind(userId).all();
  return r.results || [];
}
function deepMerge(target, patch) {
  const out = Array.isArray(target) ? [...target] : { ...(target || {}) };
  for (const k of Object.keys(patch)) {
    const v = patch[k];
    if (v && typeof v === "object" && !Array.isArray(v) && out[k] && typeof out[k] === "object" && !Array.isArray(out[k])) out[k] = deepMerge(out[k], v);
    else out[k] = v;
  }
  return out;
}
async function readBody(req) {
  const text = await req.text();
  if (text.length > MAX_DOC) throw Object.assign(new Error("Too large"), { status: 413 });
  const data = text ? JSON.parse(text) : {};
  if (!data || typeof data !== "object" || Array.isArray(data)) throw Object.assign(new Error("Body must be an object"), { status: 400 });
  return data;
}

// Extra rules for non-developers.
function allowedChange(role, col, existing, patch, isCreate) {
  if (role === "developer") return true;
  const keys = Object.keys(patch);
  if (role === "engineer") {
    if (col === "projects") return !isCreate && keys.every((k) => k === "checks");
    if (col === "matreqs") return isCreate && patch.status === "pending";
    return true; // logs, reports, stock
  }
  if (role === "investor") {
    if (col === "requests") return isCreate;
    if (col === "milestones") {
      if (isCreate || !existing || existing.status !== "verified") return false;
      return keys.every((k) => ["status", "approvedAt", "dispute"].includes(k)) && ["approved", "disputed"].includes(patch.status);
    }
  }
  return false;
}

export async function onRequest(ctx) {
  const { request: req, env } = ctx;
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const m = req.method;
  const iterations = parseInt(env.PBKDF2_ITERATIONS || "100000", 10);

  try {
    // ---------- auth ----------
    if (parts[0] === "auth") {
      if (m !== "POST") return err(405, "Method not allowed");
      if (parts[1] === "signup") {
        const { name = "", email = "", password = "" } = await readBody(req);
        const em = String(email).trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return err(400, "Enter a valid email address.");
        if (String(password).length < 8) return err(400, "Use a password of at least 8 characters.");
        if (await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(em).first()) return err(409, "That email already has an account.");
        const id = randHex(12), salt = randHex(16), hash = await hashPassword(String(password), salt, iterations);
        await env.DB.prepare("INSERT INTO users (id, email, name, pass_hash, salt, iterations, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .bind(id, em, String(name).trim().slice(0, 120), hash, salt, iterations, Date.now()).run();
        const c = await startSession(env, id);
        return json({ user: { id, name: String(name).trim(), email: em } }, 200, { "set-cookie": c });
      }
      if (parts[1] === "login") {
        const { email = "", password = "" } = await readBody(req);
        const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(String(email).trim().toLowerCase()).first();
        if (!u) return err(400, "Email or password is wrong.");
        const h = await hashPassword(String(password), u.salt, u.iterations || iterations);
        if (!safeEqual(h, u.pass_hash)) return err(400, "Email or password is wrong.");
        const c = await startSession(env, u.id);
        return json({ user: { id: u.id, name: u.name, email: u.email } }, 200, { "set-cookie": c });
      }
      if (parts[1] === "logout") {
        const t = cookie(req, "st_s");
        if (t) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
        return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
      }
      return err(404, "Not found");
    }

    const user = await currentUser(req, env);
    if (!user) return err(401, "Please sign in.");

    // ---------- who am I ----------
    if (parts[0] === "me" && m === "GET") return json({ user, memberships: await memberships(env, user.id) });

    // ---------- all data this user may see ----------
    if (parts[0] === "data" && m === "GET") {
      const ms = await memberships(env, user.id);
      const docs = {};
      COLS.forEach((c) => (docs[c] = []));
      for (const { pid, role } of ms) {
        const cols = READ[role] || [];
        const qs = cols.map(() => "?").join(",");
        const r = await env.DB.prepare(
          `SELECT col, id, data FROM docs WHERE pid = ? AND col IN (${qs}) ORDER BY updated_at DESC LIMIT 3000`
        ).bind(pid, ...cols).all();
        for (const row of r.results || []) docs[row.col].push({ id: row.id, data: JSON.parse(row.data) });
      }
      return json({ memberships: ms, docs });
    }

    // ---------- documents ----------
    if (parts[0] === "docs" && parts.length === 3) {
      const [, col, id] = parts;
      if (!COLS.includes(col) || !ID_RE.test(id)) return err(400, "Bad path");
      const row = await env.DB.prepare("SELECT pid, data FROM docs WHERE col = ? AND id = ?").bind(col, id).first();
      const existing = row ? JSON.parse(row.data) : null;

      if (m === "DELETE") {
        if (!row) return json({ ok: true });
        if ((await roleOn(env, user.id, row.pid)) !== "developer") return err(403, "Only the developer can delete.");
        await env.DB.prepare("DELETE FROM docs WHERE col = ? AND id = ?").bind(col, id).run();
        return json({ ok: true });
      }
      if (m !== "PUT" && m !== "PATCH") return err(405, "Method not allowed");
      const body = await readBody(req);

      // New project: whoever creates it becomes its developer.
      if (col === "projects" && !row) {
        if (m !== "PUT") return err(404, "Project not found");
        const now = Date.now();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO docs (col, id, pid, data, created_at, updated_at) VALUES ('projects', ?, ?, ?, ?, ?)").bind(id, id, JSON.stringify(body), now, now),
          env.DB.prepare("INSERT INTO members (project_id, user_id, role, created_at) VALUES (?, ?, 'developer', ?)").bind(id, user.id, now),
        ]);
        return json({ ok: true });
      }

      const pid = col === "projects" ? id : row ? row.pid : String(body.pid || "");
      if (!pid) return err(400, "Missing project");
      const role = await roleOn(env, user.id, pid);
      if (!role || !(WRITE[role] || []).includes(col)) return err(403, "You don't have access to change this.");
      if (m === "PATCH" && !row) return err(404, "Not found");
      if (!allowedChange(role, col, existing, body, !row)) return err(403, "You don't have access to change this.");

      let next = m === "PATCH" ? deepMerge(existing, body) : body;
      if (col !== "projects") next.pid = pid;
      const text = JSON.stringify(next);
      if (text.length > MAX_DOC) return err(413, "Too large");
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO docs (col, id, pid, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at"
      ).bind(col, id, pid, text, now, now).run();
      return json({ ok: true });
    }

    // ---------- photo upload (R2) ----------
    if (parts[0] === "upload" && m === "POST") {
      const pid = url.searchParams.get("pid") || "";
      const role = await roleOn(env, user.id, pid);
      if (role !== "developer" && role !== "engineer") return err(403, "You can't upload to this project.");
      const type = (req.headers.get("content-type") || "").split(";")[0];
      if (!["image/jpeg", "image/png", "image/webp"].includes(type)) return err(415, "Upload a JPEG, PNG or WebP photo.");
      const len = parseInt(req.headers.get("content-length") || "0", 10);
      if (len > MAX_PHOTO) return err(413, "Photo is too large.");
      const ext = type === "image/png" ? "png" : type === "image/webp" ? "webp" : "jpg";
      const key = `${pid}/${randHex(12)}.${ext}`;
      await env.PHOTOS.put(key, req.body, { httpMetadata: { contentType: type }, customMetadata: { by: user.id } });
      return json({ id: key, url: "/api/photo/" + key.split("/").map(encodeURIComponent).join("/") });
    }
    if (parts[0] === "photo" && m === "GET" && parts.length === 3) {
      const [, pid, file] = parts;
      if (!(await roleOn(env, user.id, pid))) return err(403, "Not allowed");
      const obj = await env.PHOTOS.get(`${pid}/${file}`);
      if (!obj) return err(404, "Not found");
      return new Response(obj.body, { headers: { "content-type": obj.httpMetadata?.contentType || "image/jpeg", "cache-control": "private, max-age=86400" } });
    }

    // ---------- team & invites ----------
    if (parts[0] === "members" && m === "GET") {
      const pid = url.searchParams.get("pid") || "";
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can see the team.");
      const mem = await env.DB.prepare("SELECT u.name, u.email, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY m.created_at").bind(pid).all();
      const inv = await env.DB.prepare("SELECT code, role, name, email FROM invites WHERE project_id = ? AND used_by IS NULL ORDER BY created_at DESC").bind(pid).all();
      return json({ members: mem.results || [], invites: inv.results || [] });
    }
    if (parts[0] === "invites" && parts[1] === "accept" && m === "POST") {
      const { code = "" } = await readBody(req);
      const inv = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(String(code)).first();
      if (!inv || inv.used_by) return err(400, "That invite link isn't valid any more.");
      const now = Date.now();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO members (project_id, user_id, role, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role").bind(inv.project_id, user.id, inv.role, now),
        env.DB.prepare("UPDATE invites SET used_by = ?, used_at = ? WHERE code = ?").bind(user.id, now, inv.code),
      ]);
      return json({ pid: inv.project_id, role: inv.role });
    }
    if (parts[0] === "invites" && !parts[1] && m === "POST") {
      const { pid = "", role = "", name = "", email = "" } = await readBody(req);
      if (!ROLES.includes(role)) return err(400, "Choose a role.");
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can invite people.");
      const code = randCode(12);
      await env.DB.prepare("INSERT INTO invites (code, project_id, role, name, email, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(code, pid, role, String(name).slice(0, 120), String(email).slice(0, 200), user.id, Date.now()).run();
      return json({ code });
    }

    return err(404, "Not found");
  } catch (e) {
    if (e && e.status) return err(e.status, e.message);
    if (e instanceof SyntaxError) return err(400, "Invalid JSON");
    console.error(e);
    return err(500, "Something went wrong.");
  }
}
