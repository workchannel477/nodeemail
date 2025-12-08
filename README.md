# Email Management Stack (Node.js API + Alpine.js UI)

Full-stack email sender rebuilt to run with a Node.js/Express API (cPanel-compatible if Node is enabled, also deployable to Vercel/Netlify functions) and a static Alpine.js + Tailwind dashboard. Email dispatch uses AWS SES by default, with optional SMTP + proxy support. Data lives in JSON files under `data/`.

## Architecture
- **Backend**: Node.js/Express (`api/server.js`) with routes for auth, users/admin, jobs, rate limits, and IP rotation. Email sending uses AWS SES SDK; optional `MAIL_TRANSPORT=smtp` will use SMTP via Nodemailer (supports proxy and IP rotation list).
- **Frontend**: Static Alpine.js + Tailwind pages in `public/`; `public/config.js` sets the API base (defaults to `/api` on the same domain).
- **Data**: JSON stores (`data/auth.json`, `data/email-jobs.json`, `data/ip-rotation.json`, `data/rate-limit.json`).

## Repo layout
- `api/server.js` — Express API entry.
- `public/` — static UI; upload as-is to your web root (or `dist/` after `npm run build`).
- `public/config.js` — set `window.APP_CONFIG.apiBase` if your API runs elsewhere.
- `data/` — JSON storage (auto-created/defaulted).
- `scripts/build.js` — copies `public/` to `dist/` for upload.

## SMTP pool & rotation
- SMTP credentials are managed in the Admin panel only; the user dashboard no longer accepts SMTP usernames or passwords.
- Admins can add multiple SMTP providers (Mailtrap, SES SMTP endpoint, Sender, etc.) and set the rotation threshold (defaults to every 200 sent emails).
- Users provide only From/Subject/Recipients + body when creating jobs; sending pulls from the rotating SMTP pool.

## Local quick start (Node)
1) Install Node 18+.  
2) `npm install`  
3) Backend/API + static UI: `npm start` (same as `npm run api`, serves API + static files).  
4) Frontend dev server: `npm run dev` (serves http://localhost:8080, calls the API at http://localhost:5000 by default).

## Deploy
- **Render (single service)**: create a Web Service, set Build Command to `npm run build`, Start Command to `npm start`, and add a persistent disk mounted at `/app/data` so the JSON stores survive restarts. Optionally set `API_BASE`/`API_BASE_OVERRIDE` to force a specific API base URL (default is same-origin).  
- **cPanel (Node app)**: ensure Node support is enabled on your plan. Upload code, run `npm install`, and point the app to `api/server.js` (e.g., via Passenger/Setup Node App). Set env vars in cPanel.
- **Vercel/Netlify** (UI): build and deploy `dist/` (see `netlify.toml` for defaults). Set `API_BASE_OVERRIDE` env to your API URL.
- **VPS/Managed Node (recommended for API)**: Render/Fly/DigitalOcean App Platform. Use the included `Dockerfile` or `Procfile`. Persist `data/`.
- **Static hosts**: use `npm run build` and upload `dist/` for the UI; point it to your API via `public/config.js` or `API_BASE_OVERRIDE`.

## Configuration (.env)
- `SECRET_KEY`, `SESSION_TIMEOUT`
- Rate limits: `MAX_EMAILS_PER_MINUTE`, `MAX_REQUESTS_PER_MINUTE`, `EMAIL_BATCH_SIZE`
- SMTP defaults: `DEFAULT_SMTP_HOST`, `DEFAULT_SMTP_PORT`
- CORS: `CORS_ORIGINS`
- Frontend base: `API_BASE` or `API_BASE_OVERRIDE` (optional; defaults to same-origin, `http://localhost:5000` in dev)
- SES: `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SES_FROM`, `MAIL_TRANSPORT=ses|smtp`

## IP rotation & proxies
- Proxies are loaded from `data/ip-rotation.json` and rotated per batch.  
- For SES, a proxy is used only for the HTTPS client; SES still sends from AWS IPs.  
- For SMTP (`MAIL_TRANSPORT=smtp`), a `proxy` or SOCKS proxy is passed to Nodemailer.

## Deliverability notes
- SES (or reputable SMTP) gives the best inbox placement; verify sender domains and set SPF/DKIM/DMARC.  
- Chunking and rate limits are enforced; adjust `EMAIL_BATCH_SIZE` and per-minute caps to avoid provider throttling.  
- Shared hosting (cPanel) may throttle outbound SMTP or background processes—Vercel/Netlify or a small VPS (Fly.io/Render/DigitalOcean) is typically more reliable for sustained email jobs.

## Default admin
- Auto-created if `data/auth.json` is empty:  
  - Username: `admin`  
  - Password: `admin123` (change immediately via admin panel or `/admin/users/{id}/change-password`).
