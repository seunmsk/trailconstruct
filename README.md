# TrailConstruct — Cloudflare deployment

Every stage, on record. Construction tracking for Nigerian developers, site engineers and investors.

**What's in this folder**

| Path | What it is |
|---|---|
| `public/index.html` | The whole web app (home page, sign-up, the three workspaces) |
| `public/_headers` | Security headers |
| `functions/api/[[path]].js` | The API: accounts, data, photo uploads, invites, role checks |
| `schema.sql` | Database tables |
| `wrangler.toml` | Cloudflare settings (database + photo storage) |

It runs on **Cloudflare Pages** (the website and API), **D1** (the database) and **R2** (photo storage).

---

## Deploy (about 20 minutes)

You need a Cloudflare account, Node.js 18+ and this folder on your computer (or in a GitHub repo).

```bash
npm install
npx wrangler login
```

**1. Create the database and copy its ID**

```bash
npx wrangler d1 create trailconstruct-db
```

Paste the `database_id` it prints into `wrangler.toml`, replacing `PASTE-YOUR-D1-DATABASE-ID-HERE`.

**2. Tables**

The app creates its own tables the first time it runs. (You can also run `npm run db:remote` to create them by hand.)

**3. Create photo storage**

```bash
npx wrangler r2 bucket create trailconstruct-photos
```

(R2 must be switched on once in the Cloudflare dashboard: R2 → Get started.)

**4. Deploy**

```bash
npm run deploy
```

The first time, it asks for a project name (use `trailconstruct`). You get a link like `https://trailconstruct.pages.dev`.

**5. Your own domain**

Cloudflare dashboard → Workers & Pages → trailconstruct → Custom domains → add your domain.

### Deploying from GitHub instead

Push this folder to a GitHub repo, then in Cloudflare: Workers & Pages → Create → Pages → Connect to Git.
Build command: *(leave empty)*. Build output directory: `public`.
Then under the project's Settings → Bindings, add a **D1 database** binding named `DB` (trailconstruct-db) and an **R2 bucket** binding named `PHOTOS` (trailconstruct-photos). The tables are created automatically on first use.

---

## Google address search (optional, recommended)

With a Google Maps key, the developer types the site address, picks it from Google's suggestions, and the site's GPS pin is saved automatically. Without a key, the app still works: the developer taps "Use my current location" on site or enters coordinates.

1. Go to https://console.cloud.google.com, create a project and add a billing account (Google gives a monthly free allowance; small usage normally costs nothing, but check Google's current pricing).
2. APIs & Services → Library → enable **Maps JavaScript API** and **Places API (New)**.
3. APIs & Services → Credentials → **Create credentials → API key**.
4. Restrict the key:
   - Application restrictions → **Websites** → add `https://trailconstruct.pages.dev/*` and your own domain, e.g. `https://trailconstruct.com/*`.
   - API restrictions → only **Maps JavaScript API** and **Places API (New)**.
5. Cloudflare → Workers & Pages → trailconstruct → Settings → **Variables and Secrets** → Add → type **Secret**, name `GOOGLE_MAPS_KEY`, paste the key → Save, then redeploy (Deployments → Retry deployment).

This key is used in the browser, so Google requires the website restriction above to stop others using it.

---

## Invite emails (optional, recommended)

Without this, invites are links the developer sends on WhatsApp or copies. With it, each engineer or investor with an email address also gets an email: "You've been added to [project] on TrailConstruct", with a **Join the project** button.

The app uses **Resend** (resend.com) to send email.

1. Sign up at resend.com.
2. **Domains → Add domain** → your domain (e.g. `trailconstruct.com`). Resend shows a few DNS records. If your domain is on Cloudflare, add them in Cloudflare → your domain → DNS. Wait for Resend to show **Verified**.
3. **API keys → Create API key** (sending access) and copy it.
4. Cloudflare → Workers & Pages → trailconstruct → Settings → Variables and Secrets → add two **Secrets**:
   - `RESEND_API_KEY` = the key
   - `EMAIL_FROM` = `TrailConstruct <invites@trailconstruct.com>` (any address on your verified domain)
5. Retry the latest deployment.

Until a domain is verified, Resend only delivers to your own Resend account email, so other people won't receive invites yet.

**Enterprise enquiries:** the "Talk to us" form on the home page saves every enquiry in the database (D1 Console: `SELECT * FROM leads ORDER BY created_at DESC;`). Add a third Secret, `CONTACT_TO` = the email address that should receive them, to also get each enquiry by email.

---

## Try it on your computer first

```bash
npm install
npm run db:local
npm run dev
```

Open http://localhost:8788.

---

## How accounts and roles work

- A developer signs up from **Get started** and creates a project. They become that project's developer.
- From the sign-up flow or **Project → Team**, the developer creates invite links for site engineers and investors and sends them on WhatsApp.
- Opening an invite link asks the person to create an account (or sign in), then adds them to the project with that role.
- The server checks every read and write against the person's role:
  - **Investors** only receive the project summary, investor updates, milestones and their own update requests. They never receive site logs, engineer reports, materials or expenses.
  - **Site engineers** can post logs, weekly reports, material requests and store entries, and tick checklists. They can't send investor updates, change budgets or delete anything.
  - **Developers** have full access to their own projects.
- Photos are stored privately in R2 and only served to members of that project.
- Passwords are hashed (PBKDF2-SHA256). Sessions last 30 days, in a secure HTTP-only cookie.

## Live GPS photos

On your own domain the browser can use the phone's GPS. When a photo has no location in it, the app asks the phone for its position and checks it against the site's pin before accepting the photo.

---

## Before real customers use it

- **Plan:** password hashing uses CPU time. `PBKDF2_ITERATIONS` in `wrangler.toml` is set to 20000 so sign-up works on the free plan. On Workers Paid (around $5/month), raise it to 100000, the Workers maximum. Existing passwords keep working.
- **Rate limiting:** in Cloudflare → Security → WAF → Rate limiting rules, limit `/api/auth/*` (for example 10 requests a minute per IP) to slow down password guessing.
- **Backups:** D1 has Time Travel (point-in-time restore, 30 days on paid plans). Also export regularly: `npx wrangler d1 export trailconstruct-db --remote --output=backup.sql`.
- **Password reset:** not built yet. It needs an email service (for example Resend or Postmark). Until then, reset passwords manually.
- **Payments:** subscription billing (Paystack/Flutterwave) and the escrow partner are not connected yet.
- **Legal:** terms of use and a privacy policy (Nigeria Data Protection Act) before launch.
