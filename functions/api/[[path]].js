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
// Site records can't be changed or deleted once these windows pass: daily updates and the
// store log after 24 hours, weekly reports after 7 days.
const LOCK_MS = { logs: 24 * 3600 * 1000, stock: 24 * 3600 * 1000, reports: 7 * 24 * 3600 * 1000 };
const LOCKED_COLS = Object.keys(LOCK_MS);
const INVITE_DAYS = 14;
const LOGIN_WINDOW_MS = 15 * 60 * 1000, LOGIN_MAX_FAILS = 8;

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
function allowedChange(role, col, existing, patch, isCreate, method) {
  if (role === "developer") return true;
  const keys = Object.keys(patch);
  // Only developers may replace a whole record; everyone else creates new records or makes small, allowed changes.
  if (!isCreate && method === "PUT" && col !== "reports") return false;
  if (role === "engineer") {
    if (col === "projects") return !isCreate && method === "PATCH" && keys.every((k) => k === "checks") && patch.checks && typeof patch.checks === "object" && Object.values(patch.checks).every((v) => typeof v === "boolean");
    if (col === "matreqs") return isCreate && patch.status === "pending";
    return true; // logs, reports, stock
  }
  if (role === "investor") {
    if (col === "requests") return isCreate;
    if (col === "milestones") {
      if (isCreate || method !== "PATCH" || !existing || existing.status !== "verified") return false;
      return keys.every((k) => ["status", "approvedAt", "dispute"].includes(k)) && ["approved", "disputed"].includes(patch.status);
    }
  }
  return false;
}


// Creates the tables on first use, so no manual database setup is needed.
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, pass_hash TEXT NOT NULL, salt TEXT NOT NULL, iterations INTEGER NOT NULL, created_at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)",
  "CREATE TABLE IF NOT EXISTS members (project_id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK (role IN ('developer','engineer','investor')), created_at INTEGER NOT NULL, PRIMARY KEY (project_id, user_id))",
  "CREATE INDEX IF NOT EXISTS members_user ON members(user_id)",
  "CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, project_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('developer','engineer','investor')), name TEXT, email TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, used_by TEXT, used_at INTEGER)",
  "CREATE INDEX IF NOT EXISTS invites_project ON invites(project_id)",
  "CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, pid TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (col, id))",
  "CREATE INDEX IF NOT EXISTS docs_pid_col ON docs(pid, col, updated_at)",
  "CREATE TABLE IF NOT EXISTS deleted (col TEXT NOT NULL, id TEXT NOT NULL, pid TEXT NOT NULL, deleted_at INTEGER NOT NULL, PRIMARY KEY (col, id))",
  "CREATE INDEX IF NOT EXISTS deleted_pid ON deleted(pid, deleted_at)",
  "CREATE TABLE IF NOT EXISTS login_fails (email TEXT NOT NULL, at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS login_fails_email ON login_fails(email, at)",
  "CREATE TABLE IF NOT EXISTS leads (id TEXT PRIMARY KEY, name TEXT, company TEXT, email TEXT, phone TEXT, sites TEXT, message TEXT, created_at INTEGER NOT NULL)",
];
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady || !env.DB) return;
  await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)));
  schemaReady = true;
}


const escHtml = (s) => String(s || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ROLE_NAME = { developer: "a developer", engineer: "a site engineer", investor: "an investor" };
// Sends the invite by email when an email service is set up (Resend). Returns true if sent.
async function sendInviteEmail(env, { to, name, role, projectName, inviter, link }) {
  if (!env.RESEND_API_KEY || !to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return false;
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#15202a">
  <div style="background:#1d3546;color:#fff;padding:18px 22px;border-bottom:4px solid #f0a500"><b style="font-size:20px">TrailConstruct</b><br><span style="font-size:13px;opacity:.8">Every stage, on record.</span></div>
  <div style="padding:22px;border:1px solid #dfe2db;border-top:0">
  <p>Hello${name ? " " + escHtml(name) : ""},</p>
  <p><b>${escHtml(inviter || "Your developer")}</b> has added you to <b>${escHtml(projectName)}</b> on TrailConstruct as ${ROLE_NAME[role] || "a team member"}.</p>
  <p>${role === "investor" ? "You'll be able to see the project's progress, site photos and download progress reports." : role === "engineer" ? "You'll post daily site updates and photos, and send a weekly report." : "You'll have full access to manage the project."}</p>
  <p style="margin:26px 0"><a href="${link}" style="background:#f0a500;color:#1b1404;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">Join the project</a></p>
  <p style="font-size:13px;color:#5b6570">Or open this link: ${link}<br>If you weren't expecting this, you can ignore this email.</p></div></div>`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM || "TrailConstruct <onboarding@resend.dev>", to: [to], subject: `You've been invited to ${projectName} on TrailConstruct`, html }),
    });
    if (!r.ok) console.error("email failed", r.status, await r.text());
    return r.ok;
  } catch (e) { console.error("email error", e); return false; }
}

export async function onRequest(ctx) {
  const { request: req, env } = ctx;
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const m = req.method;
  const iterations = parseInt(env.PBKDF2_ITERATIONS || "20000", 10);

  try {
    await ensureSchema(env);
    // ---------- public settings for the web app ----------
    if (parts[0] === "config" && m === "GET") return json({ mapsKey: env.GOOGLE_MAPS_KEY || "", email: !!env.RESEND_API_KEY });

    // ---------- enterprise / contact enquiries (no login needed) ----------
    if (parts[0] === "contact" && m === "POST") {
      const b = await readBody(req);
      if (b.website) return json({ ok: true }); // hidden spam trap
      const name = String(b.name || "").trim().slice(0, 120), email = String(b.email || "").trim().slice(0, 200), phone = String(b.phone || "").trim().slice(0, 40);
      if (!name || (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && !phone)) return err(400, "Add your name and an email or phone number.");
      const lead = { id: randHex(10), name, company: String(b.company || "").trim().slice(0, 160), email, phone, sites: String(b.sites || "").slice(0, 20), message: String(b.message || "").trim().slice(0, 2000) };
      await env.DB.prepare("INSERT INTO leads (id, name, company, email, phone, sites, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(lead.id, lead.name, lead.company, lead.email, lead.phone, lead.sites, lead.message, Date.now()).run();
      if (env.RESEND_API_KEY && env.CONTACT_TO) {
        try {
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
            body: JSON.stringify({
              from: env.EMAIL_FROM || "TrailConstruct <onboarding@resend.dev>", to: [env.CONTACT_TO], reply_to: lead.email || undefined,
              subject: `Enterprise enquiry: ${lead.company || lead.name} (${lead.sites || "?"} sites)`,
              html: `<p><b>${escHtml(lead.name)}</b>${lead.company ? " · " + escHtml(lead.company) : ""}</p><p>Email: ${escHtml(lead.email) || "—"}<br>Phone / WhatsApp: ${escHtml(lead.phone) || "—"}<br>Sites: ${escHtml(lead.sites) || "—"}</p><p>${escHtml(lead.message).replace(/\n/g, "<br>")}</p>`,
            }),
          });
        } catch (e) { console.error("lead email", e); }
      }
      return json({ ok: true });
    }

    // ---------- health check (no login needed; shows setup status only) ----------
    if (parts[0] === "health" && m === "GET") {
      const out = { database_connected: !!env.DB, photo_storage_connected: !!env.PHOTOS, tables: [], missing_tables: [] };
      if (env.DB) {
        try {
          const r = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
          out.tables = (r.results || []).map((x) => x.name).filter((n) => !n.startsWith("_cf") && n !== "sqlite_sequence");
        } catch (e) { out.database_error = String(e && e.message || e).slice(0, 200); }
        out.missing_tables = ["users", "sessions", "members", "invites", "docs"].filter((t) => !out.tables.includes(t));
      }
      out.ok = out.database_connected && out.photo_storage_connected && !out.missing_tables.length && !out.database_error;
      return json(out);
    }

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
        const em = String(email).trim().toLowerCase().slice(0, 200);
        const since = Date.now() - LOGIN_WINDOW_MS;
        const fails = await env.DB.prepare("SELECT COUNT(*) AS n FROM login_fails WHERE email = ? AND at > ?").bind(em, since).first();
        if (fails && fails.n >= LOGIN_MAX_FAILS) return err(429, "Too many attempts. Wait 15 minutes and try again.");
        const fail = async () => {
          await env.DB.batch([
            env.DB.prepare("INSERT INTO login_fails (email, at) VALUES (?, ?)").bind(em, Date.now()),
            env.DB.prepare("DELETE FROM login_fails WHERE at < ?").bind(Date.now() - 24 * 3600 * 1000),
          ]);
          return err(400, "Email or password is wrong.");
        };
        const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(em).first();
        if (!u) return fail();
        const h = await hashPassword(String(password), u.salt, u.iterations || iterations);
        if (!safeEqual(h, u.pass_hash)) return fail();
        await env.DB.prepare("DELETE FROM login_fails WHERE email = ?").bind(em).run();
        if ((u.iterations || 0) < iterations) { // strengthen older password hashes when the setting is raised
          const salt = randHex(16), nh = await hashPassword(String(password), salt, iterations);
          await env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ?, iterations = ? WHERE id = ?").bind(nh, salt, iterations, u.id).run();
        }
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
    if (parts[0] === "me" && m === "DELETE") {
      const { password = "" } = await readBody(req);
      const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
      if (!safeEqual(await hashPassword(String(password), u.salt, u.iterations || iterations), u.pass_hash)) return err(400, "That password is wrong.");
      const ms = await memberships(env, user.id);
      for (const { pid, role } of ms) {
        if (role !== "developer") continue;
        const others = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE project_id = ? AND role = 'developer' AND user_id <> ?").bind(pid, user.id).first();
        if (!others || !others.n) return err(409, "You're the only developer on a project. Delete the project or make someone else a developer first.");
      }
      await env.DB.batch([
        env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
        env.DB.prepare("DELETE FROM members WHERE user_id = ?").bind(user.id),
        env.DB.prepare("DELETE FROM login_fails WHERE email = ?").bind(user.email),
        env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id),
      ]);
      return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
    }

    // ---------- all data this user may see ----------
    // Full load the first time (since=0); after that only what changed since the last pull.
    if (parts[0] === "data" && m === "GET") {
      const now = Date.now();
      const since = Math.max(0, parseInt(url.searchParams.get("since") || "0", 10) || 0);
      const ms = await memberships(env, user.id);
      const docs = {}, deleted = [];
      COLS.forEach((c) => (docs[c] = []));
      for (const { pid, role } of ms) {
        const cols = READ[role] || [];
        const qs = cols.map(() => "?").join(",");
        const r = await env.DB.prepare(
          `SELECT col, id, data, created_at FROM docs WHERE pid = ? AND col IN (${qs}) AND updated_at > ? ORDER BY updated_at DESC LIMIT 20000`
        ).bind(pid, ...cols, since).all();
        for (const row of r.results || []) {
          const d = JSON.parse(row.data);
          if (LOCKED_COLS.includes(row.col)) d._locked = now - row.created_at > LOCK_MS[row.col];
          docs[row.col].push({ id: row.id, data: d });
        }
        if (since) {
          const dr = await env.DB.prepare(`SELECT col, id FROM deleted WHERE pid = ? AND col IN (${qs}) AND deleted_at > ?`).bind(pid, ...cols, since).all();
          for (const row of dr.results || []) deleted.push({ col: row.col, id: row.id });
        }
      }
      // 5 seconds of overlap so nothing written during this request is missed.
      return json({ memberships: ms, docs, deleted, now: now - 5000, full: !since });
    }

    // ---------- documents ----------
    if (parts[0] === "docs" && parts.length === 3) {
      const [, col, id] = parts;
      if (!COLS.includes(col) || !ID_RE.test(id)) return err(400, "Bad path");
      const row = await env.DB.prepare("SELECT pid, data, created_at FROM docs WHERE col = ? AND id = ?").bind(col, id).first();
      const existing = row ? JSON.parse(row.data) : null;
      const locked = row && LOCKED_COLS.includes(col) && Date.now() - row.created_at > LOCK_MS[col];

      if (m === "DELETE") {
        if (!row) return json({ ok: true });
        if ((await roleOn(env, user.id, row.pid)) !== "developer") return err(403, "Only the developer can delete.");
        if (locked) return err(403, "This site record is now locked and stays on record.");
        const now = Date.now();
        if (col === "projects") {
          // Remove the whole project: records, team, invites and photos.
          await env.DB.batch([
            env.DB.prepare("DELETE FROM docs WHERE pid = ?").bind(id),
            env.DB.prepare("DELETE FROM members WHERE project_id = ?").bind(id),
            env.DB.prepare("DELETE FROM invites WHERE project_id = ?").bind(id),
            env.DB.prepare("DELETE FROM deleted WHERE pid = ?").bind(id),
          ]);
          if (env.PHOTOS) {
            let cursor;
            do {
              const list = await env.PHOTOS.list({ prefix: id + "/", cursor, limit: 1000 });
              const keys = list.objects.map((o) => o.key);
              if (keys.length) await env.PHOTOS.delete(keys);
              cursor = list.truncated ? list.cursor : undefined;
            } while (cursor);
          }
          return json({ ok: true });
        }
        await env.DB.batch([
          env.DB.prepare("DELETE FROM docs WHERE col = ? AND id = ?").bind(col, id),
          env.DB.prepare("INSERT INTO deleted (col, id, pid, deleted_at) VALUES (?, ?, ?, ?) ON CONFLICT(col, id) DO UPDATE SET deleted_at = excluded.deleted_at").bind(col, id, row.pid, now),
        ]);
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
      if (!allowedChange(role, col, existing, body, !row, m)) return err(403, "You don't have access to change this.");
      if (locked) {
        // Once locked, a site record is fixed. The developer may only mark a weekly report as used.
        const onlyStatus = role === "developer" && col === "reports" && m === "PATCH" && Object.keys(body).every((k) => k === "status");
        if (!onlyStatus) return err(403, "This site record is now locked and stays on record.");
      }
      delete body._locked;

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
      const len = parseInt(req.headers.get("content-length") || "", 10);
      if (!len) return err(411, "Photo size missing. Please try again.");
      if (len > MAX_PHOTO) return err(413, "Photo is too large.");
      const ext = type === "image/png" ? "png" : type === "image/webp" ? "webp" : "jpg";
      const key = `${pid}/${randHex(12)}.${ext}`;
      const bytes = await req.arrayBuffer();
      if (bytes.byteLength > MAX_PHOTO) return err(413, "Photo is too large.");
      await env.PHOTOS.put(key, bytes, { httpMetadata: { contentType: type }, customMetadata: { by: user.id } });
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
      const mem = await env.DB.prepare("SELECT u.id, u.name, u.email, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY m.created_at").bind(pid).all();
      const inv = await env.DB.prepare("SELECT code, role, name, email, created_at FROM invites WHERE project_id = ? AND used_by IS NULL AND created_at > ? ORDER BY created_at DESC").bind(pid, Date.now() - INVITE_DAYS * 864e5).all();
      return json({ me: user.id, members: mem.results || [], invites: inv.results || [] });
    }
    if (parts[0] === "members" && m === "DELETE") {
      const pid = url.searchParams.get("pid") || "", uid = url.searchParams.get("user") || "";
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can remove people.");
      const target = await roleOn(env, uid, pid);
      if (!target) return json({ ok: true });
      if (target === "developer") {
        const devs = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE project_id = ? AND role = 'developer'").bind(pid).first();
        if (devs.n <= 1) return err(409, "A project needs at least one developer.");
      }
      await env.DB.prepare("DELETE FROM members WHERE project_id = ? AND user_id = ?").bind(pid, uid).run();
      return json({ ok: true });
    }
    if (parts[0] === "invites" && parts[1] && parts[1] !== "accept" && m === "DELETE") {
      const inv = await env.DB.prepare("SELECT project_id FROM invites WHERE code = ?").bind(parts[1]).first();
      if (!inv) return json({ ok: true });
      if ((await roleOn(env, user.id, inv.project_id)) !== "developer") return err(403, "Only the developer can cancel invites.");
      await env.DB.prepare("DELETE FROM invites WHERE code = ?").bind(parts[1]).run();
      return json({ ok: true });
    }
    if (parts[0] === "invites" && parts[1] === "accept" && m === "POST") {
      const { code = "" } = await readBody(req);
      const inv = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(String(code)).first();
      if (!inv || inv.used_by || Date.now() - inv.created_at > INVITE_DAYS * 864e5) return err(400, "That invite link isn't valid any more. Ask the developer for a new one.");
      const now = Date.now();
      const current = await roleOn(env, user.id, inv.project_id);
      // Never lower someone's access by accident: a developer who opens an investor link stays a developer.
      const rank = { investor: 1, engineer: 2, developer: 3 };
      const role = current && rank[current] >= rank[inv.role] ? current : inv.role;
      await env.DB.batch([
        env.DB.prepare("INSERT INTO members (project_id, user_id, role, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role").bind(inv.project_id, user.id, role, now),
        env.DB.prepare("UPDATE invites SET used_by = ?, used_at = ? WHERE code = ?").bind(user.id, now, inv.code),
      ]);
      return json({ pid: inv.project_id, role });
    }
    if (parts[0] === "invites" && !parts[1] && m === "POST") {
      const { pid = "", role = "", name = "", email = "" } = await readBody(req);
      if (!ROLES.includes(role)) return err(400, "Choose a role.");
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can invite people.");
      const code = randCode(12);
      await env.DB.prepare("INSERT INTO invites (code, project_id, role, name, email, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(code, pid, role, String(name).slice(0, 120), String(email).slice(0, 200), user.id, Date.now()).run();
      const proj = await env.DB.prepare("SELECT data FROM docs WHERE col = 'projects' AND id = ?").bind(pid).first();
      const projectName = proj ? JSON.parse(proj.data).name || "a project" : "a project";
      const emailed = await sendInviteEmail(env, { to: String(email).trim(), name: String(name).trim(), role, projectName, inviter: user.name, link: `${url.origin}/?invite=${code}` });
      return json({ code, emailed });
    }

    return err(404, "Not found");
  } catch (e) {
    if (e && e.status) return err(e.status, e.message);
    if (e instanceof SyntaxError) return err(400, "Invalid JSON");
    console.error(e);
    return err(500, "Something went wrong.");
  }
}
