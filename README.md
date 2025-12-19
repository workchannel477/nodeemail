# Email Management Stack (Node.js API + Alpine.js UI)

Full-stack email sender rebuilt to run with a Node.js/Express API (cPanel-compatible if Node is enabled, also deployable to Vercel/Netlify functions) and an Alpine.js + Tailwind dashboard bundled via Webpack. Email dispatch uses AWS SES by default, with optional SMTP + proxy support. Data lives in JSON files under `data/`.

## Architecture
- **Backend**: Node.js/Express (`api/server.js`) with routes for auth, users/admin, jobs, rate limits, and IP rotation. Email sending can use AWS SES (`MAIL_TRANSPORT=ses`), Zoho Mail's HTTPS API (`MAIL_TRANSPORT=zoho`), or traditional SMTP via Nodemailer (`MAIL_TRANSPORT=smtp`, supports proxies and IP rotation).
- **Frontend**: Alpine.js + Tailwind pages bundled by Webpack from `src/` with HTML templates in `public/`; `public/config.js` sets the API base (defaults to `/api` on the same domain).
- **Data**: JSON stores (`data/auth.json`, `data/email-jobs.json`, `data/mail-providers.json`, `data/smtp-pool.json`, `data/ip-rotation.json`, `data/rate-limit.json`).

## Repo layout
- `api/server.js` – Express API entry.
- `src/` – frontend entrypoints (`user.js`, `admin.js`) bundled by Webpack.
- `public/` – HTML templates + `config.js` (copied into dist); built assets land in `dist/` after `npm run build`.
- `data/` – JSON storage (auto-created/defaulted).
- `dist/` – generated static output served by Express in production.

## SMTP/API transports
- SMTP credentials are managed in the Admin panel only; the user dashboard no longer accepts SMTP usernames or passwords.
- Admins can add multiple SMTP servers (Mailtrap, SES SMTP endpoint, Sender, etc.) and set the rotation threshold (defaults to every 200 sent emails).
- Admins can also define HTTPS/API providers (Zoho Mail API or AWS SES HTTPS) with per-minute/per-day quotas; batches are rotated across this pool before falling back to the legacy SMTP rotation when no API providers are enabled.
- Set `MAIL_TRANSPORT=ses` to send over AWS SES HTTPS, `MAIL_TRANSPORT=zoho` to send through the Zoho Mail API (requires OAuth credentials + account ID), or leave it as `smtp` to use the rotating pool.
- Users provide only From/Subject/Recipients + body when creating jobs; attachments can be supplied via the job payload (each attachment needs `filename` and base64 `content`). API-based transports (Zoho/SES) submit those as HTTPS form-data, while SMTP deliveries embed them with Nodemailer.

### Provider rotation & quotas
- Persistent config lives in `data/mail-providers.json`. Each provider has `type` (`smtp`, `ses`, or `zoho`), credentials, and quota caps. Quotas are tracked by day + rolling one-minute windows.
- The Admin dashboard now exposes an "API & SMTP Providers" section where you can add/edit/delete providers, toggle them on/off, and reset usage counters. Behind the scenes the `/admin/providers` REST endpoints manage the JSON file.
- When at least one provider is enabled, every job batch is routed through the provider pool (Zoho form-post, SES HTTPS, or raw SMTP). If all providers are disabled or missing, the system falls back to the legacy SMTP rotation controlled by `data/smtp-pool.json`.
- Error details bubble back to the activity log so you can see when a particular provider hit its quota or returned an upstream error.

### Attachments
- `POST /api/jobs` and `PUT /api/jobs/:id` accept an `attachments` array. Each entry must include `filename`, base64 `content`, and an optional `encoding` (defaults to `base64`) plus optional `contentType`.
- Attachments are persisted with the job payload (base64 inside `data/email-jobs.json`). During dispatch they're converted back to buffers and forwarded to Zoho (multipart/form-data), SES (raw email via Nodemailer), or SMTP (Nodemailer) so every transport can deliver identical payloads.

### Replaying legacy Zoho jobs
- Use the admin-only API `POST /admin/jobs/replay` to re-send previously delivered jobs through the new provider pool. Request body:
  ```json
  {
    "transport": "zoho",       // filter by last-known transport (set `null` to replay everything)
    "statuses": ["sent"],      // job statuses to include
    "limit": 10,               // optional cap on number of jobs
    "dryRun": true,            // when true, just preview matches
    "includeUnknown": true     // also replay jobs that predate transport metadata
  }
  ```
- A CLI helper is available via `npm run replay:zoho` (configurable through `REPLAY_API_BASE`, `REPLAY_ADMIN_USER`, `REPLAY_ADMIN_PASS`, `REPLAY_TRANSPORT`, `REPLAY_LIMIT`, `REPLAY_DRY_RUN`, or matching `--api`, `--username`, `--password`, `--transport`, `--limit`, `--dry-run` flags). The script logs in via `/auth/login` and calls the replay endpoint, so the API must be running.
- End-users can replay a single job they own via `POST /api/jobs/{jobId}/replay` (the dashboard’s Retry/Resend button now uses this route). This resets the job state and dispatches it through the current provider rotation without requiring admin privileges.
- Jobs now store `transportHint`, `lastTransport`, and provider snapshots, so future replays only touch batches previously dispatched via Zoho (or whichever provider you choose).

## Local quick start (Node)
1) Install Node 18+.  
2) `npm install`  
3) Dev (frontend + backend together): `npm run dev` (Webpack dev server on http://localhost:8080 proxies API calls to http://localhost:5000 while Nodemon runs the API).  
4) API only: `npm run api` (or `npm run api:dev` with Nodemon).  
5) Production: `npm run build` then `npm start` (serves `dist/` from Express on port 5000 by default).

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
- SMTP network tuning (optional): `SMTP_CONNECTION_TIMEOUT_MS` (default 15000), `SMTP_SOCKET_TIMEOUT_MS` (default 20000)
- Zoho Mail API (optional): `MAIL_TRANSPORT=zoho`, `ZOHO_CLIENT_ID`, `ZOHO_CLIENT_SECRET`, `ZOHO_REFRESH_TOKEN`, `ZOHO_ACCOUNT_ID`, `ZOHO_FROM_ADDRESS`, plus optional `ZOHO_DOMAIN`, `ZOHO_ACCOUNTS_HOST`, `ZOHO_MAIL_HOST`.
- CORS: `CORS_ORIGINS`
- Frontend base: `API_BASE` or `API_BASE_OVERRIDE` (optional; defaults to same-origin, `http://localhost:5000` in dev)
- SES: `MAIL_TRANSPORT=ses`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SES_FROM`

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

## Syncing `/data` to GitHub
All persistent state (users, jobs, SMTP pool, logs, etc.) lives under `/data`. To keep that folder versioned in Git without running extra CLI scripts, call the admin-only API endpoint:

```
POST /admin/data-sync
Authorization: Bearer <ADMIN TOKEN>
Content-Type: application/json

{
  "message": "chore: sync data folder",   // optional commit message
  "push": true                            // set false to skip `git push`
}
```

The endpoint stages `data/`, creates a commit (if there are changes), and optionally pushes to the current remote. It returns a JSON body indicating whether a commit occurred and if it was pushed. Use it from a secure admin UI, a curl command, or an automation hook.

⚠️ `/data` contains credentials, recipient lists, and logs. Only call this endpoint in trusted environments targeting a private repository, and consider redacting sensitive files before syncing.
