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
// Password reset links last 1 hour and work once. At most 3 per account and 10 per network address an hour.
const RESET_MS = 60 * 60 * 1000, RESET_MAX_PER_USER = 3, RESET_MAX_PER_IP = 10;
const FROM_DEFAULT = "TrailConstruct <no-reply@trailconstruct.com>";
const ALERT_TO_DEFAULT = "hello@trailconstruct.com";
// ---------- billing (manual bank transfer for now) ----------
const BANK = { bank: "Wema Bank", name: "Eppcheck Technologies Ltd", number: "0126784194" };
const VAT = 0.075, DAY = 864e5;
const GRACE_DAYS = 7;        // a new project can be used for 7 days before the pilot is paid
const AFTER_EXPIRY_DAYS = 3; // after a paid period ends, 3 more days before the project becomes read-only
const KINDS = { pilot: { months: 3, label: "3-month pilot" }, monthly: { months: 1, label: "1 month" }, yearly: { months: 12, label: "12 months" } };
const addMonths = (t, n) => { const d = new Date(t); d.setUTCMonth(d.getUTCMonth() + n); return d.getTime(); };
const fmtDate = (t) => new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "Africa/Lagos" });
const naira = (n) => "₦" + Math.round(n).toLocaleString("en-NG");
function priceFor(kind, devProjects) {
  const rate = devProjects >= 5 ? 22000 : 25000;
  const net = kind === "pilot" ? rate * 3 : kind === "yearly" ? rate * 10 : rate;
  return { net, vat: Math.round(net * VAT), total: Math.round(net * (1 + VAT)) };
}
// "active": paid or still in the free week. "due": paid period ended, within the 3 days' grace. "locked": read-only.
function billingState(b, now = Date.now()) {
  if (!b) return "active"; // projects from before billing started
  if (b.paid_until) {
    if (now <= b.paid_until) return "active";
    if (now <= b.paid_until + AFTER_EXPIRY_DAYS * DAY) return "due";
    return "locked";
  }
  return now <= b.grace_until ? "trial" : "locked";
}
const ADMIN_DEFAULT = "seunmsk@gmail.com";
// Photos: taken more than this long before upload are marked "posted later" (e.g. queued offline).
const PHOTO_LATE_MS = 6 * 3600 * 1000, PHOTO_MAX_AGE_MS = 72 * 3600 * 1000;
const isAdmin = (env, user) => !!user && String(env.ADMIN_EMAILS || ADMIN_DEFAULT).toLowerCase().split(/[\s,]+/).includes(String(user.email).toLowerCase());
function distM(a, b) {
  const R = 6371000, r = (x) => (x * Math.PI) / 180, dLat = r(b.lat - a.lat), dLng = r(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(r(a.lat)) * Math.cos(r(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));

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
  "CREATE TABLE IF NOT EXISTS photo_meta (key TEXT PRIMARY KEY, pid TEXT NOT NULL, user_id TEXT NOT NULL, uploaded_at INTEGER NOT NULL, orig_hash TEXT, taken_at INTEGER, lat REAL, lng REAL, dist REAL, verdict TEXT, late INTEGER DEFAULT 0)",
  "CREATE INDEX IF NOT EXISTS photo_meta_hash ON photo_meta(pid, orig_hash)",
  "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, pid TEXT NOT NULL, user_id TEXT, user_name TEXT, role TEXT, action TEXT NOT NULL, col TEXT, doc_id TEXT, at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS audit_pid ON audit(pid, at)",
  "CREATE TABLE IF NOT EXISTS billing (pid TEXT PRIMARY KEY, plan_after TEXT NOT NULL DEFAULT 'monthly', paid_until INTEGER, grace_until INTEGER NOT NULL, reminded TEXT, created_at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS payments (ref TEXT PRIMARY KEY, pid TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, sent_at INTEGER, done_at INTEGER, done_by TEXT)",
  "CREATE INDEX IF NOT EXISTS payments_pid ON payments(pid, created_at)",
  "CREATE TABLE IF NOT EXISTS alerts (kind TEXT PRIMARY KEY, at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS password_resets (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)",
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
      body: JSON.stringify({ from: env.EMAIL_FROM || FROM_DEFAULT, to: [to], subject: `You've been invited to ${projectName} on TrailConstruct`, html }),
    });
    if (!r.ok) console.error("email failed", r.status, await r.text());
    return r.ok;
  } catch (e) { console.error("email error", e); return false; }
}

// Activity log. Repeated edits of the same record by the same person within 10 minutes are folded into one line.
async function logActivity(env, { pid, user, role, action, col = null, doc = null }) {
  try {
    const now = Date.now();
    const prev = await env.DB.prepare("SELECT id FROM audit WHERE pid = ? AND user_id = ? AND action = ? AND IFNULL(doc_id,'') = ? AND at > ? ORDER BY at DESC LIMIT 1")
      .bind(pid, user ? user.id : null, action, doc || "", now - 10 * 60 * 1000).first();
    if (prev) await env.DB.prepare("UPDATE audit SET at = ? WHERE id = ?").bind(now, prev.id).run();
    else await env.DB.prepare("INSERT INTO audit (pid, user_id, user_name, role, action, col, doc_id, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(pid, user ? user.id : null, user ? (user.name || user.email) : null, role || null, action, col, doc, now).run();
  } catch (e) { console.error("audit", e); }
}
// Emails hello@ when something breaks on the server. At most one email per kind of error every 30 minutes.
async function sendAlert(env, kind, subject, detail) {
  try {
    if (!env.RESEND_API_KEY || !env.DB) return;
    const now = Date.now(), k = String(kind).slice(0, 120);
    const last = await env.DB.prepare("SELECT at FROM alerts WHERE kind = ?").bind(k).first();
    if (last && now - last.at < 30 * 60 * 1000) return;
    await env.DB.prepare("INSERT INTO alerts (kind, at) VALUES (?, ?) ON CONFLICT(kind) DO UPDATE SET at = excluded.at").bind(k, now).run();
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM || FROM_DEFAULT, to: [env.ALERT_TO || ALERT_TO_DEFAULT], subject: "TrailConstruct alert: " + subject,
        html: `<p><b>${escHtml(subject)}</b></p><pre style="white-space:pre-wrap;font-size:12px">${escHtml(String(detail).slice(0, 3000))}</pre><p style="font-size:12px;color:#5b6570">You'll get at most one email like this every 30 minutes.</p>` }),
    });
  } catch (e) { console.error("alert", e); }
}
const ACTIONS = {
  logs: ["posted a daily update", "edited a daily update", "deleted a daily update"],
  reports: ["sent a weekly report", "edited a weekly report", "deleted a weekly report"],
  updates: ["sent an investor update", "edited an investor update", "deleted an investor update"],
  expenses: ["recorded spending", "edited spending", "deleted spending"],
  requests: ["sent a request", "updated a request", "deleted a request"],
  matreqs: ["requested materials", "updated a material request", "deleted a material request"],
  stock: ["logged the site store", "edited a store entry", "deleted a store entry"],
  milestones: ["added a milestone", "updated a milestone", "deleted a milestone"],
  projects: ["created the project", "edited project details", "deleted the project"],
};

async function sendMail(env, to, subject, inner) {
  if (!env.RESEND_API_KEY || !to) return false;
  const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#15202a"><div style="background:#1d3546;color:#fff;padding:18px 22px;border-bottom:4px solid #f0a500"><b style="font-size:20px">TrailConstruct</b><br><span style="font-size:13px;opacity:.8">Every stage, on record.</span></div><div style="padding:22px;border:1px solid #dfe2db;border-top:0;font-size:15px;line-height:1.5">${inner}</div></div>`;
  try {
    const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM || FROM_DEFAULT, to: Array.isArray(to) ? to : [to], reply_to: env.REPLY_TO || "hello@trailconstruct.com", subject, html }) });
    if (!r.ok) console.error("mail failed", r.status, await r.text());
    return r.ok;
  } catch (e) { console.error("mail error", e); return false; }
}
const btn = (href, text) => `<p style="margin:24px 0"><a href="${href}" style="background:#f0a500;color:#1b1404;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">${text}</a></p>`;
const bankBlock = (ref, total) => `<table style="border-collapse:collapse;font-size:15px;margin:8px 0 4px">${[["Amount", naira(total)], ["Bank", BANK.bank], ["Account name", BANK.name], ["Account number", BANK.number], ["Narration", ref]].map(([a, b]) => `<tr><td style="padding:4px 16px 4px 0;color:#5b6570">${a}</td><td style="padding:4px 0"><b>${b}</b></td></tr>`).join("")}</table>`;
async function projectName(env, pid) {
  const r = await env.DB.prepare("SELECT data FROM docs WHERE col = 'projects' AND id = ?").bind(pid).first();
  return r ? JSON.parse(r.data).name || "your project" : "your project";
}
async function developersOf(env, pid) {
  const r = await env.DB.prepare("SELECT u.id, u.name, u.email FROM members m JOIN users u ON u.id = m.user_id WHERE m.project_id = ? AND m.role = 'developer'").bind(pid).all();
  return r.results || [];
}
async function devProjectCount(env, userId) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE user_id = ? AND role = 'developer'").bind(userId).first();
  return r ? r.n : 1;
}
async function openPayment(env, pid) {
  return env.DB.prepare("SELECT * FROM payments WHERE pid = ? AND status IN ('awaiting','sent') ORDER BY created_at DESC LIMIT 1").bind(pid).first();
}
async function newPayment(env, pid, userId, kind) {
  const price = priceFor(kind, await devProjectCount(env, userId));
  const ref = "TC-" + randCode(6).toUpperCase();
  await env.DB.prepare("INSERT INTO payments (ref, pid, user_id, kind, amount, status, created_at) VALUES (?, ?, ?, ?, ?, 'awaiting', ?)").bind(ref, pid, userId, kind, price.total, Date.now()).run();
  return env.DB.prepare("SELECT * FROM payments WHERE ref = ?").bind(ref).first();
}
// Reminder emails go out when anyone on the project opens it, so no scheduler is needed.
async function billingReminders(env, origin, pid, b) {
  try {
    const now = Date.now(), st = billingState(b, now);
    let key = null, subject = "", body = "";
    const name = await projectName(env, pid);
    if (b.paid_until && st === "active" && b.paid_until - now <= 7 * DAY) { key = "7d:" + b.paid_until; subject = `${name}: your TrailConstruct subscription ends on ${fmtDate(b.paid_until)}`; body = `<p>Your subscription for <b>${escHtml(name)}</b> ends on <b>${fmtDate(b.paid_until)}</b>.</p><p>Renew before then so your site engineers can keep posting and your investors keep getting updates.</p>`; }
    if (b.paid_until && st === "due") { key = "due:" + b.paid_until; subject = `${name}: your TrailConstruct subscription has ended`; body = `<p>Your subscription for <b>${escHtml(name)}</b> ended on <b>${fmtDate(b.paid_until)}</b>.</p><p>The project becomes read-only on <b>${fmtDate(b.paid_until + AFTER_EXPIRY_DAYS * DAY)}</b> unless it's renewed. Nothing is deleted.</p>`; }
    if (!b.paid_until && st === "trial" && b.grace_until - now <= 2 * DAY) { key = "trial:" + b.grace_until; subject = `${name}: pay for your pilot to keep using TrailConstruct`; body = `<p>Your free first week for <b>${escHtml(name)}</b> ends on <b>${fmtDate(b.grace_until)}</b>.</p><p>Pay for your 3-month pilot before then to keep posting. After that date the project becomes read-only until payment is confirmed.</p>`; }
    if (!key || (b.reminded || "").split(",").includes(key)) return;
    await env.DB.prepare("UPDATE billing SET reminded = ? WHERE pid = ?").bind([...(b.reminded || "").split(",").filter(Boolean).slice(-5), key].join(","), pid).run();
    const devs = await developersOf(env, pid);
    for (const d of devs) await sendMail(env, d.email, subject, `<p>Hello ${escHtml(d.name || "")},</p>${body}${btn(origin + "/#developer", "Renew in TrailConstruct")}<p style="font-size:13px;color:#5b6570">Questions? Reply to this email.</p>`);
  } catch (e) { console.error("reminder", e); }
}

async function sendResetEmail(env, { to, name, link }) {
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#15202a">
  <div style="background:#1d3546;color:#fff;padding:18px 22px;border-bottom:4px solid #f0a500"><b style="font-size:20px">TrailConstruct</b><br><span style="font-size:13px;opacity:.8">Every stage, on record.</span></div>
  <div style="padding:22px;border:1px solid #dfe2db;border-top:0">
  <p>Hello${name ? " " + escHtml(name) : ""},</p>
  <p>Someone asked to reset the password for your TrailConstruct account. Click the button to choose a new password.</p>
  <p style="margin:26px 0"><a href="${link}" style="background:#f0a500;color:#1b1404;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">Choose a new password</a></p>
  <p style="font-size:13px;color:#5b6570">This link works once and expires in 1 hour. Or open: ${link}<br><br>If you didn't ask for this, ignore this email. Your password won't change.</p></div></div>`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM || FROM_DEFAULT, to: [to], reply_to: env.REPLY_TO || "hello@trailconstruct.com", subject: "Reset your TrailConstruct password", html }),
    });
    if (!r.ok) console.error("reset email failed", r.status, await r.text());
    return r.ok;
  } catch (e) { console.error("reset email error", e); return false; }
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
      if (env.RESEND_API_KEY) {
        try {
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
            body: JSON.stringify({
              from: env.EMAIL_FROM || FROM_DEFAULT, to: [env.CONTACT_TO || "hello@trailconstruct.com"], reply_to: lead.email || undefined,
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
      // Forgot password: always answers the same way, so it can't be used to find out who has an account.
      if (parts[1] === "forgot") {
        if (!env.RESEND_API_KEY) return err(503, "Password reset by email isn't switched on yet. Contact hello@trailconstruct.com.");
        const { email = "" } = await readBody(req);
        const em = String(email).trim().toLowerCase().slice(0, 200);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return err(400, "Enter a valid email address.");
        const now = Date.now(), ipKey = "reset-ip:" + (req.headers.get("cf-connecting-ip") || "unknown");
        const ipN = await env.DB.prepare("SELECT COUNT(*) AS n FROM login_fails WHERE email = ? AND at > ?").bind(ipKey, now - RESET_MS).first();
        if (ipN && ipN.n >= RESET_MAX_PER_IP) return err(429, "Too many reset requests. Wait an hour and try again.");
        await env.DB.prepare("INSERT INTO login_fails (email, at) VALUES (?, ?)").bind(ipKey, now).run();
        const u = await env.DB.prepare("SELECT id, name, email FROM users WHERE email = ?").bind(em).first();
        if (u) {
          const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM password_resets WHERE user_id = ? AND created_at > ?").bind(u.id, now - RESET_MS).first();
          if (!recent || recent.n < RESET_MAX_PER_USER) {
            const token = randHex(32);
            await env.DB.batch([
              env.DB.prepare("DELETE FROM password_resets WHERE expires_at < ?").bind(now - 24 * 3600 * 1000),
              env.DB.prepare("INSERT INTO password_resets (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)").bind(await sha256(token), u.id, now, now + RESET_MS),
            ]);
            const origin = env.APP_URL || url.origin;
            await sendResetEmail(env, { to: u.email, name: u.name, link: `${origin}/#reset-${token}` });
          }
        }
        return json({ ok: true });
      }
      if (parts[1] === "reset") {
        const { token = "", password = "" } = await readBody(req);
        if (!/^[a-f0-9]{64}$/.test(String(token))) return err(400, "This reset link isn't valid. Ask for a new one.");
        if (String(password).length < 8) return err(400, "Use a password of at least 8 characters.");
        const now = Date.now(), th = await sha256(String(token));
        const r = await env.DB.prepare("SELECT * FROM password_resets WHERE token_hash = ?").bind(th).first();
        if (!r || r.used_at || r.expires_at < now) return err(400, "This reset link has expired or was already used. Ask for a new one.");
        const u = await env.DB.prepare("SELECT id, name, email FROM users WHERE id = ?").bind(r.user_id).first();
        if (!u) return err(400, "This reset link isn't valid. Ask for a new one.");
        const salt = randHex(16), hash = await hashPassword(String(password), salt, iterations);
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ?, iterations = ? WHERE id = ?").bind(hash, salt, iterations, u.id),
          env.DB.prepare("UPDATE password_resets SET used_at = ? WHERE token_hash = ?").bind(now, th),
          env.DB.prepare("DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL").bind(u.id),
          env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id), // signs out every other device
          env.DB.prepare("DELETE FROM login_fails WHERE email = ?").bind(u.email),
        ]);
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
    if (parts[0] === "me" && m === "GET" && !parts[1]) return json({ user, admin: isAdmin(env, user), memberships: await memberships(env, user.id) });
    if (parts[0] === "me" && m === "DELETE" && !parts[1]) {
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

    // ---------- change password (signed in) ----------
    if (parts[0] === "me" && parts[1] === "password" && m === "POST") {
      const { current = "", next = "" } = await readBody(req);
      if (String(next).length < 8) return err(400, "Use a new password of at least 8 characters.");
      const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
      if (!safeEqual(await hashPassword(String(current), u.salt, u.iterations || iterations), u.pass_hash)) return err(400, "Your current password is wrong.");
      const salt = randHex(16), hash = await hashPassword(String(next), salt, iterations), t = cookie(req, "st_s");
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ?, iterations = ? WHERE id = ?").bind(hash, salt, iterations, user.id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token <> ?").bind(user.id, t || ""), // sign out other devices
        env.DB.prepare("DELETE FROM password_resets WHERE user_id = ?").bind(user.id),
      ]);
      return json({ ok: true });
    }

    // ---------- billing ----------
    if (parts[0] === "billing") {
      const b0 = m === "GET" ? null : await readBody(req);
      const pid = m === "GET" ? url.searchParams.get("pid") || "" : String(b0.pid || "");
      const role = await roleOn(env, user.id, pid);
      if (!role) return err(403, "Not allowed");
      let b = await env.DB.prepare("SELECT * FROM billing WHERE pid = ?").bind(pid).first();
      const state = billingState(b);
      if (m === "GET") {
        if (b) ctx.waitUntil(billingReminders(env, env.APP_URL || url.origin, pid, b));
        const out = { state, paidUntil: b && b.paid_until, graceUntil: b && b.grace_until, readOnlyFrom: b ? (b.paid_until ? b.paid_until + AFTER_EXPIRY_DAYS * DAY : b.grace_until) : null };
        if (role !== "developer") return json(out);
        const pay = b ? await openPayment(env, pid) : null;
        const n = await devProjectCount(env, user.id);
        return json({ ...out, planAfter: b && b.plan_after, bank: BANK, payment: pay && { ref: pay.ref, kind: pay.kind, label: KINDS[pay.kind].label, amount: pay.amount, status: pay.status, sentAt: pay.sent_at },
          prices: Object.fromEntries(Object.keys(KINDS).map((k) => [k, priceFor(k, n)])) });
      }
      if (role !== "developer") return err(403, "Only the developer manages payment.");
      if (!b) return err(400, "This project doesn't need payment.");
      if (parts[1] === "renew" && m === "POST") {
        const kind = b0.kind === "yearly" ? "yearly" : "monthly";
        const open = await openPayment(env, pid);
        if (open && open.status === "sent") return err(409, "We're still confirming your last transfer.");
        if (open) await env.DB.prepare("UPDATE payments SET status = 'cancelled', done_at = ? WHERE ref = ?").bind(Date.now(), open.ref).run();
        const kindToUse = !b.paid_until ? "pilot" : kind; // the pilot comes first
        await newPayment(env, pid, user.id, kindToUse);
        await env.DB.prepare("UPDATE billing SET plan_after = ? WHERE pid = ?").bind(kind, pid).run();
        return json({ ok: true });
      }
      if (parts[1] === "sent" && m === "POST") {
        const pay = await openPayment(env, pid);
        if (!pay) return err(400, "There's no payment waiting. Start a renewal first.");
        if (pay.status !== "sent") {
          await env.DB.prepare("UPDATE payments SET status = 'sent', sent_at = ? WHERE ref = ?").bind(Date.now(), pay.ref).run();
          const name = await projectName(env, pid);
          ctx.waitUntil(sendMail(env, env.ALERT_TO || ALERT_TO_DEFAULT, `Payment to confirm: ${naira(pay.amount)} · ${pay.ref}`,
            `<p><b>${escHtml(user.name || user.email)}</b> says they've transferred <b>${naira(pay.amount)}</b> for <b>${escHtml(name)}</b>.</p><p>Reference: <b>${pay.ref}</b><br>For: ${KINDS[pay.kind].label}<br>Email: ${escHtml(user.email)}</p>${btn((env.APP_URL || url.origin) + "/#admin", "Open payments page")}<p style="font-size:13px;color:#5b6570">Check your ${BANK.bank} app for the reference, then confirm it on the payments page.</p>`));
          await logActivity(env, { pid, user, role, action: `marked a ${naira(pay.amount)} transfer as sent (${pay.ref})` });
        }
        return json({ ok: true });
      }
      return err(404, "Not found");
    }
    if (parts[0] === "admin" && parts[1] === "payments") {
      if (!isAdmin(env, user)) return err(403, "Not allowed");
      if (m === "GET") {
        const q = (where) => env.DB.prepare(`SELECT p.*, u.name AS dev_name, u.email AS dev_email, d.data AS pdata, b.paid_until FROM payments p LEFT JOIN users u ON u.id = p.user_id LEFT JOIN docs d ON d.col = 'projects' AND d.id = p.pid LEFT JOIN billing b ON b.pid = p.pid WHERE ${where} ORDER BY COALESCE(p.sent_at, p.created_at) DESC LIMIT 100`).all();
        const shape = (x) => ({ ref: x.ref, pid: x.pid, project: x.pdata ? JSON.parse(x.pdata).name : "(deleted project)", dev: x.dev_name, email: x.dev_email, kind: x.kind, label: KINDS[x.kind] ? KINDS[x.kind].label : x.kind, amount: x.amount, status: x.status, createdAt: x.created_at, sentAt: x.sent_at, doneAt: x.done_at, paidUntil: x.paid_until });
        const open = await q("p.status IN ('sent','awaiting')"), done = await q("p.status IN ('confirmed','rejected')");
        return json({ open: (open.results || []).map(shape), done: (done.results || []).slice(0, 30).map(shape) });
      }
      const ref = parts[2] || "", action = parts[3] || "";
      const pay = await env.DB.prepare("SELECT * FROM payments WHERE ref = ?").bind(ref).first();
      if (!pay || !["awaiting", "sent"].includes(pay.status)) return err(400, "That payment isn't waiting for confirmation.");
      const now = Date.now(), name = await projectName(env, pay.pid), dev = await env.DB.prepare("SELECT name, email FROM users WHERE id = ?").bind(pay.user_id).first();
      if (action === "confirm" && m === "POST") {
        const b = await env.DB.prepare("SELECT * FROM billing WHERE pid = ?").bind(pay.pid).first();
        const from = b && b.paid_until && b.paid_until > now ? b.paid_until : now;
        const until = addMonths(from, KINDS[pay.kind].months);
        await env.DB.batch([
          env.DB.prepare("UPDATE payments SET status = 'confirmed', done_at = ?, done_by = ? WHERE ref = ?").bind(now, user.email, ref),
          env.DB.prepare("UPDATE billing SET paid_until = ? WHERE pid = ?").bind(until, pay.pid),
        ]);
        const net = Math.round(pay.amount / (1 + VAT));
        if (dev) ctx.waitUntil(sendMail(env, dev.email, `Payment received: ${naira(pay.amount)} for ${name}`,
          `<p>Hello ${escHtml(dev.name || "")},</p><p>We've received your payment. Thank you.</p><table style="border-collapse:collapse;font-size:15px">${[["Receipt", ref], ["Project", escHtml(name)], ["For", KINDS[pay.kind].label], ["Amount before VAT", naira(net)], ["VAT (7.5%)", naira(pay.amount - net)], ["Total paid", naira(pay.amount)], ["Paid until", fmtDate(until)]].map(([a, b2]) => `<tr><td style="padding:4px 16px 4px 0;color:#5b6570">${a}</td><td style="padding:4px 0"><b>${b2}</b></td></tr>`).join("")}</table><p style="font-size:13px;color:#5b6570;margin-top:18px">Trail Construct Limited · Surulere, Lagos · hello@trailconstruct.com</p>`));
        await logActivity(env, { pid: pay.pid, user: { id: null, name: "TrailConstruct" }, action: `confirmed payment ${ref} (${naira(pay.amount)}). Paid until ${fmtDate(until)}` });
        return json({ ok: true, paidUntil: until });
      }
      if (action === "reject" && m === "POST") {
        await env.DB.prepare("UPDATE payments SET status = 'awaiting', sent_at = NULL WHERE ref = ?").bind(ref).run();
        if (dev) ctx.waitUntil(sendMail(env, dev.email, `We couldn't find your transfer for ${name}`,
          `<p>Hello ${escHtml(dev.name || "")},</p><p>We haven't received a transfer with the narration <b>${ref}</b> yet. If you've paid, reply to this email with your transfer receipt and we'll sort it out. If not, here are the details again:</p>${bankBlock(ref, pay.amount)}`));
        return json({ ok: true });
      }
      return err(404, "Not found");
    }

    // ---------- activity log (developer only) ----------
    if (parts[0] === "audit" && m === "GET") {
      const pid = url.searchParams.get("pid") || "";
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can see the activity log.");
      const r = await env.DB.prepare("SELECT user_name AS who, role, action, col, doc_id AS doc, at FROM audit WHERE pid = ? ORDER BY at DESC LIMIT 300").bind(pid).all();
      return json({ items: r.results || [] });
    }

    // ---------- full backup download (admin only) ----------
    if (parts[0] === "admin" && parts[1] === "backup" && m === "GET") {
      if (!isAdmin(env, user)) return err(403, "Not allowed");
      const out = { exported_at: new Date().toISOString() };
      for (const t of ["users", "members", "invites", "docs", "deleted", "audit", "photo_meta", "leads", "billing", "payments"]) {
        const r = await env.DB.prepare(`SELECT * FROM ${t}`).all();
        out[t] = (r.results || []).map((row) => { if (t === "users") { const { pass_hash, salt, ...rest } = row; return rest; } return row; });
      }
      return new Response(JSON.stringify(out), { headers: { "content-type": "application/json", "content-disposition": `attachment; filename="trailconstruct-backup-${out.exported_at.slice(0, 10)}.json"`, "cache-control": "no-store" } });
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
            env.DB.prepare("DELETE FROM audit WHERE pid = ?").bind(id),
            env.DB.prepare("DELETE FROM photo_meta WHERE pid = ?").bind(id),
            env.DB.prepare("DELETE FROM billing WHERE pid = ?").bind(id),
            env.DB.prepare("DELETE FROM payments WHERE pid = ? AND status <> 'confirmed'").bind(id),
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
        if (ACTIONS[col]) await logActivity(env, { pid: row.pid, user, role: "developer", action: ACTIONS[col][2], col, doc: id });
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
        await env.DB.prepare("INSERT INTO billing (pid, plan_after, grace_until, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(pid) DO NOTHING")
          .bind(id, (body.plan && body.plan.billing) === "yearly" ? "yearly" : "monthly", now + GRACE_DAYS * DAY, now).run();
        await newPayment(env, id, user.id, "pilot");
        await logActivity(env, { pid: id, user, role: "developer", action: ACTIONS.projects[0], col, doc: id });
        return json({ ok: true });
      }

      const pid = col === "projects" ? id : row ? row.pid : String(body.pid || "");
      if (!pid) return err(400, "Missing project");
      const bl = await env.DB.prepare("SELECT * FROM billing WHERE pid = ?").bind(pid).first();
      if (billingState(bl) === "locked") return err(402, "This project is read-only because its subscription isn't paid. The developer can renew it from the dashboard.");
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
      // Photo details come from the server's own record of each upload, not from what the phone says.
      if (Array.isArray(next.photos) && next.photos.length) {
        const keys = next.photos.map((ph) => ph && ph.id).filter((k) => typeof k === "string").slice(0, 60);
        if (keys.length) {
          const r = await env.DB.prepare(`SELECT * FROM photo_meta WHERE key IN (${keys.map(() => "?").join(",")})`).bind(...keys).all();
          const meta = Object.fromEntries((r.results || []).map((x) => [x.key, x]));
          next.photos = next.photos.map((ph) => {
            const x = ph && meta[ph.id];
            if (!x || x.pid !== pid) return ph;
            return { ...ph, v: x.verdict || ph.v, dist: x.dist, gps: x.lat != null ? { lat: x.lat, lng: x.lng } : null,
              takenAt: x.taken_at ? new Date(x.taken_at).toISOString() : ph.takenAt, uploadedAt: new Date(x.uploaded_at).toISOString(), late: !!x.late, checked: true };
          });
        }
      }
      const isCheckTick = col === "projects" && m === "PATCH" && Object.keys(body).every((k) => k === "checks");
      const text = JSON.stringify(next);
      if (text.length > MAX_DOC) return err(413, "Too large");
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO docs (col, id, pid, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at"
      ).bind(col, id, pid, text, now, now).run();
      if (ACTIONS[col]) await logActivity(env, { pid, user, role, action: isCheckTick ? "ticked off checklist items" : ACTIONS[col][row ? 1 : 0], col, doc: id });
      return json({ ok: true });
    }

    // ---------- has this photo been posted before? (checked when the photo is picked) ----------
    if (parts[0] === "photo-check" && m === "GET") {
      const pid = url.searchParams.get("pid") || "", hh = url.searchParams.get("h") || "";
      if (!(await roleOn(env, user.id, pid))) return err(403, "Not allowed");
      if (!/^[a-f0-9]{64}$/.test(hh)) return json({ dup: null });
      const d = await env.DB.prepare("SELECT uploaded_at FROM photo_meta WHERE pid = ? AND orig_hash = ? LIMIT 1").bind(pid, hh).first();
      return json({ dup: d ? new Date(d.uploaded_at).toISOString() : null });
    }

    // ---------- photo upload (R2) ----------
    if (parts[0] === "upload" && m === "POST") {
      const pid = url.searchParams.get("pid") || "";
      const role = await roleOn(env, user.id, pid);
      if (role !== "developer" && role !== "engineer") return err(403, "You can't upload to this project.");
      const blU = await env.DB.prepare("SELECT * FROM billing WHERE pid = ?").bind(pid).first();
      if (billingState(blU) === "locked") return err(402, "This project is read-only because its subscription isn't paid. The developer can renew it from the dashboard.");
      const type = (req.headers.get("content-type") || "").split(";")[0];
      if (!["image/jpeg", "image/png", "image/webp"].includes(type)) return err(415, "Upload a JPEG, PNG or WebP photo.");
      const len = parseInt(req.headers.get("content-length") || "", 10);
      if (!len) return err(411, "Photo size missing. Please try again.");
      if (len > MAX_PHOTO) return err(413, "Photo is too large.");
      const ext = type === "image/png" ? "png" : type === "image/webp" ? "webp" : "jpg";
      const key = `${pid}/${randHex(12)}.${ext}`;
      // What the phone says about the photo. The server checks it against the site pin and its own clock.
      const now = Date.now(), h = (n) => req.headers.get(n) || "";
      const origHash = /^[a-f0-9]{64}$/.test(h("x-orig-hash")) ? h("x-orig-hash") : null;
      let takenAt = Date.parse(h("x-taken-at")); if (!isFinite(takenAt)) takenAt = null;
      let lat = parseFloat(h("x-lat")), lng = parseFloat(h("x-lng"));
      const hasGps = isFinite(lat) && isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
      if (!hasGps) { lat = null; lng = null; }
      if (takenAt && takenAt > now + 10 * 60 * 1000) return err(422, "This photo's time is in the future. Check the date and time on your phone, then take it again.");
      if (takenAt && now - takenAt > PHOTO_MAX_AGE_MS) return err(422, "This photo was taken more than 3 days ago. Take a new photo on site.");
      if (origHash) {
        const dup = await env.DB.prepare("SELECT uploaded_at FROM photo_meta WHERE pid = ? AND orig_hash = ? LIMIT 1").bind(pid, origHash).first();
        if (dup) return err(409, `This photo was already posted on ${new Date(dup.uploaded_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "Africa/Lagos" })}. Take a new one.`);
      }
      let dist = null, verdict = hasGps ? "gps" : "nogps";
      const proj = await env.DB.prepare("SELECT data FROM docs WHERE col = 'projects' AND id = ?").bind(pid).first();
      const pd = proj ? JSON.parse(proj.data) : {};
      const site = pd.siteLat != null && pd.siteLat !== "" && pd.siteLng != null && pd.siteLng !== "" ? { lat: +pd.siteLat, lng: +pd.siteLng } : null;
      if (!site) verdict = "nosite";
      else if (hasGps) {
        dist = Math.round(distM({ lat, lng }, site)), verdict = "onsite";
        const rad = +pd.siteRadius || 200;
        if (role === "engineer" && dist > rad) return err(422, `This photo was taken ${dist >= 1000 ? (dist / 1000).toFixed(1) + " km" : dist + " m"} from the site. Photos must be taken within ${rad} m of the site.`);
        if (dist > rad) verdict = "offsite"; // developers may add their own or drone photos
      }
      const late = takenAt && now - takenAt > PHOTO_LATE_MS ? 1 : 0;
      const bytes = await req.arrayBuffer();
      if (bytes.byteLength > MAX_PHOTO) return err(413, "Photo is too large.");
      await env.PHOTOS.put(key, bytes, { httpMetadata: { contentType: type }, customMetadata: { by: user.id } });
      await env.DB.prepare("INSERT INTO photo_meta (key, pid, user_id, uploaded_at, orig_hash, taken_at, lat, lng, dist, verdict, late) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(key, pid, user.id, now, origHash, takenAt, lat, lng, dist, verdict, late).run();
      return json({ id: key, url: "/api/photo/" + key.split("/").map(encodeURIComponent).join("/"), v: verdict, dist, uploadedAt: new Date(now).toISOString(), late: !!late, checked: true });
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
      const gone = await env.DB.prepare("SELECT name, email FROM users WHERE id = ?").bind(uid).first();
      await logActivity(env, { pid, user, role: "developer", action: `removed ${gone ? gone.name || gone.email : "someone"} (${target}) from the team` });
      return json({ ok: true });
    }
    if (parts[0] === "invites" && parts[1] && parts[1] !== "accept" && m === "DELETE") {
      const inv = await env.DB.prepare("SELECT project_id FROM invites WHERE code = ?").bind(parts[1]).first();
      if (!inv) return json({ ok: true });
      if ((await roleOn(env, user.id, inv.project_id)) !== "developer") return err(403, "Only the developer can cancel invites.");
      await env.DB.prepare("DELETE FROM invites WHERE code = ?").bind(parts[1]).run();
      await logActivity(env, { pid: inv.project_id, user, role: "developer", action: "cancelled an invite" });
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
      await logActivity(env, { pid: inv.project_id, user, role, action: `joined the project as ${ROLE_NAME[role] || role}` });
      return json({ pid: inv.project_id, role });
    }
    if (parts[0] === "invites" && !parts[1] && m === "POST") {
      const { pid = "", role = "", name = "", email = "" } = await readBody(req);
      if (!ROLES.includes(role)) return err(400, "Choose a role.");
      if ((await roleOn(env, user.id, pid)) !== "developer") return err(403, "Only the developer can invite people.");
      if (billingState(await env.DB.prepare("SELECT * FROM billing WHERE pid = ?").bind(pid).first()) === "locked") return err(402, "This project is read-only until its subscription is paid.");
      const code = randCode(12);
      await env.DB.prepare("INSERT INTO invites (code, project_id, role, name, email, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(code, pid, role, String(name).slice(0, 120), String(email).slice(0, 200), user.id, Date.now()).run();
      const proj = await env.DB.prepare("SELECT data FROM docs WHERE col = 'projects' AND id = ?").bind(pid).first();
      const projectName = proj ? JSON.parse(proj.data).name || "a project" : "a project";
      const emailed = await sendInviteEmail(env, { to: String(email).trim(), name: String(name).trim(), role, projectName, inviter: user.name, link: `${url.origin}/?invite=${code}` });
      await logActivity(env, { pid, user, role: "developer", action: `invited ${String(name).trim() || String(email).trim() || "someone"} as ${ROLE_NAME[role] || role}` });
      return json({ code, emailed });
    }

    return err(404, "Not found");
  } catch (e) {
    if (e && e.status) return err(e.status, e.message);
    if (e instanceof SyntaxError) return err(400, "Invalid JSON");
    console.error(e);
    const msg = String((e && e.message) || e);
    ctx.waitUntil(sendAlert(env, "500:" + parts.slice(0, 2).join("/") + ":" + msg.slice(0, 60), `Server error on ${m} /api/${parts.slice(0, 2).join("/")}`, `${msg}\n\n${(e && e.stack) || ""}`));
    return err(500, "Something went wrong.");
  }
}
