import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs-extra";
import { fileURLToPath } from "url";
import { v4 as uuid } from "uuid";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import { NodeHttpHandler } from "@aws-sdk/node-http-handler";
import { HttpsProxyAgent } from "https-proxy-agent";
import nodemailer from "nodemailer";
import { SocksProxyAgent } from "socks-proxy-agent";
import { createHash } from "crypto";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, "..");
const dataDir = path.join(rootDir, "data");
const logDir = path.join(rootDir, "logs");
const staticDir = fs.existsSync(path.join(rootDir, "dist"))
  ? path.join(rootDir, "dist")
  : path.join(rootDir, "public");

const authFilePath = path.join(dataDir, "auth.json");
const jobsFilePath = path.join(dataDir, "email-jobs.json");
const ipRotationFilePath = path.join(dataDir, "ip-rotation.json");
const rateLimitFilePath = path.join(dataDir, "rate-limit.json");

const app = express();
const PORT = process.env.PORT || 5000;

const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_MINUTE = parseInt(process.env.MAX_REQUESTS_PER_MINUTE || "60", 10);
const EMAIL_RATE_LIMIT = parseInt(process.env.MAX_EMAILS_PER_MINUTE || "10", 10);
const BATCH_SIZE_DEFAULT = parseInt(process.env.EMAIL_BATCH_SIZE || "50", 10);

const sessions = new Map();
const apiRate = new Map();

ensureDataFiles();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const now = Date.now();
  const entry = apiRate.get(ip) || { count: 0, timestamp: now };
  if (now - entry.timestamp > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.timestamp = now;
  }
  entry.count += 1;
  apiRate.set(ip, entry);
  if (entry.count > MAX_REQUESTS_PER_MINUTE) {
    return res.status(429).json({ message: "Too many requests. Please slow down." });
  }
  next();
});

// ---------- Helpers ----------
async function ensureDataFiles() {
  await fs.ensureDir(dataDir);
  await fs.ensureDir(logDir);
  if (!(await fs.pathExists(authFilePath))) {
    const salt = cryptoSalt();
    await fs.writeJson(authFilePath, {
      users: [
        {
          id: "admin",
          username: "admin",
          role: "admin",
          status: "active",
          salt,
          passwordHash: hashPassword("admin123", salt),
          mailboxes: [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ],
    });
  }
  if (!(await fs.pathExists(jobsFilePath))) {
    await fs.writeJson(jobsFilePath, { jobs: [] });
  }
  if (!(await fs.pathExists(ipRotationFilePath))) {
    await fs.writeJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  }
  if (!(await fs.pathExists(rateLimitFilePath))) {
    await fs.writeJson(rateLimitFilePath, { limits: {} });
  }
}

async function readJson(filePath, fallback = {}) {
  try {
    return await fs.readJson(filePath);
  } catch (err) {
    if (err.code === "ENOENT") {
      await fs.writeJson(filePath, fallback);
      return fallback;
    }
    throw err;
  }
}

async function writeJson(filePath, value) {
  await fs.writeJson(filePath, value, { spaces: 2 });
}

function hashPassword(password, salt) {
  return createHash("sha256").update(`${salt}${password}`).digest("hex");
}

function cryptoSalt() {
  return uuid().replace(/-/g, "");
}

function normalizeRecipients(recipients = []) {
  if (Array.isArray(recipients)) {
    return recipients.map((r) => String(r).trim()).filter(Boolean);
  }
  if (typeof recipients === "string") {
    return recipients
      .split(/\r?\n|,|;/)
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function extractToken(req) {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) {
    return header.substring(7).trim();
  }
  if (req.body && typeof req.body.token === "string") return req.body.token;
  return null;
}

async function getNextProxy() {
  const payload = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  const { proxies = [], currentIndex = 0 } = payload;
  if (!proxies.length) return null;
  const proxy = proxies[currentIndex % proxies.length];
  payload.currentIndex = (currentIndex + 1) % proxies.length;
  await writeJson(ipRotationFilePath, payload);
  return proxy;
}

async function checkEmailRateLimit(username) {
  const payload = await readJson(rateLimitFilePath, { limits: {} });
  payload.limits = payload.limits || {};
  const now = Date.now();
  const entries = (payload.limits[username] || []).filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
  if (entries.length >= EMAIL_RATE_LIMIT) return false;
  entries.push(now);
  payload.limits[username] = entries;
  await writeJson(rateLimitFilePath, payload);
  return true;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ message: "Missing or invalid session" });
  }
  const session = sessions.get(token);
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ message: "Session expired" });
  }
  req.user = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

// ---------- Auth ----------
app.post("/auth/login", async (req, res) => {
  const { username = "", password = "" } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  const data = await readJson(authFilePath, { users: [] });
  const user = (data.users || []).find((u) => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const expected = hashPassword(password, user.salt);
  if (expected !== user.passwordHash) return res.status(401).json({ message: "Invalid credentials" });
  if ((user.status || "active") === "suspended") {
    return res.status(403).json({ message: "Account suspended" });
  }
  const token = uuid();
  sessions.set(token, {
    token,
    username: user.username,
    role: user.role || "user",
    id: user.id,
    expiresAt: Date.now() + (parseInt(process.env.SESSION_TIMEOUT || "3600", 10) * 1000),
  });
  return res.json({
    token,
    username: user.username,
    role: user.role || "user",
    mailboxes: user.mailboxes || [],
    status: user.status || "active",
  });
});

app.post("/auth/logout", requireAuth, (req, res) => {
  const token = extractToken(req);
  if (token) sessions.delete(token);
  res.json({ message: "Logged out" });
});

app.get("/auth/me", requireAuth, async (req, res) => {
  const data = await readJson(authFilePath, { users: [] });
  const user = (data.users || []).find((u) => u.username === req.user.username);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({
    username: user.username,
    role: user.role || "user",
    mailboxes: user.mailboxes || [],
    status: user.status || "active",
  });
});

// ---------- Admin users ----------
app.get("/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  const { users = [] } = await readJson(authFilePath, { users: [] });
  res.json(
    users.map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role || "user",
      status: u.status || "active",
      mailboxes: u.mailboxes || [],
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
    }))
  );
});

app.post("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { username = "", password = "", role = "user", status = "active" } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  const payload = await readJson(authFilePath, { users: [] });
  if ((payload.users || []).some((u) => u.username === username)) {
    return res.status(409).json({ message: "Username already exists" });
  }
  const salt = cryptoSalt();
  const now = new Date().toISOString();
  const newUser = {
    id: uuid(),
    username,
    passwordHash: hashPassword(password, salt),
    salt,
    role,
    status,
    mailboxes: [],
    createdAt: now,
    updatedAt: now,
  };
  payload.users.push(newUser);
  await writeJson(authFilePath, payload);
  res.status(201).json({ message: "User created successfully", user: newUser });
});

app.put("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const updates = req.body || {};
  const payload = await readJson(authFilePath, { users: [] });
  const idx = payload.users.findIndex((u) => u.id === id);
  if (idx === -1) return res.status(404).json({ message: "User not found" });
  if (updates.username && updates.username !== payload.users[idx].username) {
    if (payload.users.some((u) => u.username === updates.username)) {
      return res.status(409).json({ message: "Username already exists" });
    }
    payload.users[idx].username = updates.username;
  }
  if (updates.role) payload.users[idx].role = updates.role;
  if (updates.status) payload.users[idx].status = updates.status;
  payload.users[idx].updatedAt = new Date().toISOString();
  await writeJson(authFilePath, payload);
  res.json({ message: "User updated successfully" });
});

app.delete("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const payload = await readJson(authFilePath, { users: [] });
  const idx = payload.users.findIndex((u) => u.id === id);
  if (idx === -1) return res.status(404).json({ message: "User not found" });
  const deleted = payload.users.splice(idx, 1)[0];
  await writeJson(authFilePath, payload);
  for (const [token, session] of sessions.entries()) {
    if (session.username === deleted.username) sessions.delete(token);
  }
  res.json({ message: "User deleted successfully" });
});

app.post("/admin/users/:id/change-password", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword = "" } = req.body || {};
  if (!newPassword) return res.status(400).json({ message: "New password is required" });
  const payload = await readJson(authFilePath, { users: [] });
  const user = payload.users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const salt = cryptoSalt();
  user.salt = salt;
  user.passwordHash = hashPassword(newPassword, salt);
  user.updatedAt = new Date().toISOString();
  await writeJson(authFilePath, payload);
  res.json({ message: "Password updated successfully" });
});

// ---------- IP rotation & rate limits ----------
app.get("/admin/ip-rotation", requireAuth, requireAdmin, async (_req, res) => {
  const data = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  res.json(data);
});

app.post("/admin/ip-rotation", requireAuth, requireAdmin, async (req, res) => {
  const { proxies = [] } = req.body || {};
  if (!Array.isArray(proxies)) return res.status(400).json({ message: "Proxies must be an array" });
  const payload = {
    proxies: proxies.map((p) => String(p).trim()).filter(Boolean),
    currentIndex: 0,
    updatedAt: new Date().toISOString(),
  };
  await writeJson(ipRotationFilePath, payload);
  res.json({ message: "IP rotation configuration updated", proxies: payload.proxies.length });
});

app.get("/admin/rate-limits", requireAuth, requireAdmin, async (_req, res) => {
  const data = await readJson(rateLimitFilePath, { limits: {} });
  res.json(data);
});

app.post("/admin/rate-limits/reset", requireAuth, requireAdmin, async (req, res) => {
  const { username } = req.body || {};
  const data = await readJson(rateLimitFilePath, { limits: {} });
  if (username) {
    delete data.limits[username];
  } else {
    data.limits = {};
  }
  await writeJson(rateLimitFilePath, data);
  res.json({ message: "Rate limits reset successfully" });
});

// ---------- Jobs ----------
app.get("/api/jobs", requireAuth, async (req, res) => {
  const { jobs = [] } = await readJson(jobsFilePath, { jobs: [] });
  const filtered = req.user.role === "admin" ? jobs : jobs.filter((j) => j.owner === req.user.username);
  res.json(filtered);
});

app.post("/api/jobs", requireAuth, async (req, res) => {
  const {
    subject = "",
    textBody = "",
    htmlBody = "",
    recipients,
    smtpUsername,
    smtpPassword,
    smtpHost,
    smtpPort,
    batchSize,
    delayBetweenBatches = 2,
    maxRetries = 3,
  } = req.body || {};
  if (!subject || !smtpUsername || !smtpPassword) {
    return res.status(400).json({ message: "subject, smtpUsername, and smtpPassword are required" });
  }
  const recipientList = normalizeRecipients(recipients);
  if (!recipientList.length) {
    return res.status(400).json({ message: "At least one recipient is required" });
  }
  const owner = req.user.role === "admin" && req.body.owner ? req.body.owner : req.user.username;
  const users = (await readJson(authFilePath, { users: [] })).users || [];
  if (!users.some((u) => u.username === owner)) {
    return res.status(400).json({ message: `Unknown owner ${owner}` });
  }
  const now = new Date().toISOString();
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = {
    id: uuid(),
    owner,
    subject,
    textBody,
    htmlBody,
    recipients: recipientList,
    smtpUsername,
    smtpPassword,
    smtpHost: smtpHost || process.env.DEFAULT_SMTP_HOST || "email-smtp.us-east-1.amazonaws.com",
    smtpPort: parseInt(smtpPort || process.env.DEFAULT_SMTP_PORT || "587", 10),
    batchSize: parseInt(batchSize || BATCH_SIZE_DEFAULT, 10),
    delayBetweenBatches: parseInt(delayBetweenBatches, 10),
    maxRetries: parseInt(maxRetries, 10),
    status: "pending",
    createdAt: now,
    updatedAt: now,
  };
  payload.jobs.push(job);
  await writeJson(jobsFilePath, payload);
  await addMailbox(owner, smtpUsername, smtpPassword);
  res.status(201).json(job);
});

app.delete("/api/jobs/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const idx = payload.jobs.findIndex(
    (job) => job.id === id && (req.user.role === "admin" || job.owner === req.user.username)
  );
  if (idx === -1) return res.status(404).json({ message: "Job not found" });
  const removed = payload.jobs.splice(idx, 1)[0];
  await writeJson(jobsFilePath, payload);
  res.json({ message: "Job deleted", job: removed });
});

app.post("/api/jobs/:id/send", requireAuth, async (req, res) => {
  const { id } = req.params;
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot trigger this job" });
  }
  const allowed = await checkEmailRateLimit(job.owner);
  if (!allowed) {
    return res.status(429).json({
      message: `Email rate limit exceeded. Maximum ${EMAIL_RATE_LIMIT} emails per minute.`,
      retryAfter: 60,
    });
  }
  job.status = "sending";
  job.updatedAt = new Date().toISOString();
  await writeJson(jobsFilePath, payload);
  try {
    const result = await sendEmailJob(job);
    job.status = result.success ? "sent" : "failed";
    job.lastSentAt = new Date().toISOString();
    job.updatedAt = new Date().toISOString();
    job.lastResult = result;
    await writeJson(jobsFilePath, payload);
    res.json({ message: "Email dispatch complete", job, result });
  } catch (err) {
    job.status = "failed";
    job.error = err.message;
    job.updatedAt = new Date().toISOString();
    await writeJson(jobsFilePath, payload);
    res.status(500).json({ message: "Failed to send email", details: err.message });
  }
});

// ---------- Overview & health ----------
app.get("/admin/overview", requireAuth, requireAdmin, async (_req, res) => {
  const users = (await readJson(authFilePath, { users: [] })).users || [];
  const jobs = (await readJson(jobsFilePath, { jobs: [] })).jobs || [];
  const ipData = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  const rateLimits = await readJson(rateLimitFilePath, { limits: {} });
  const stats = {
    totalUsers: users.length,
    activeUsers: users.filter((u) => (u.status || "active") === "active").length,
    suspendedUsers: users.filter((u) => (u.status || "active") === "suspended").length,
    totalJobs: jobs.length,
    pendingJobs: jobs.filter((j) => j.status === "pending").length,
    sentJobs: jobs.filter((j) => j.status === "sent").length,
    failedJobs: jobs.filter((j) => j.status === "failed").length,
    proxyCount: (ipData.proxies || []).length,
    activeRateLimits: Object.keys(rateLimits.limits || {}).length,
  };
  res.json({ users, jobs, ipRotation: ipData, rateLimits, stats });
});

app.get("/healthz", async (_req, res) => {
  try {
    await ensureDataFiles();
    res.json({ status: "ok", timestamp: new Date().toISOString(), sessionCount: sessions.size });
  } catch (err) {
    res.status(500).json({ status: "error", details: err.message });
  }
});

// ---------- Mailer ----------
async function sendEmailJob(job) {
  const recipients = normalizeRecipients(job.recipients);
  const batchSize = job.batchSize || BATCH_SIZE_DEFAULT;
  const results = [];
  let sentTotal = 0;
  let failedTotal = 0;

  for (let i = 0; i < recipients.length; i += batchSize) {
    const batch = recipients.slice(i, i + batchSize);
    try {
      const proxy = await getNextProxy();
      await sendBatchWithSes(job, batch, proxy);
      results.push({ success: true, sent_count: batch.length, recipients: batch, proxy });
      sentTotal += batch.length;
      if (job.delayBetweenBatches) {
        await new Promise((resolve) => setTimeout(resolve, job.delayBetweenBatches * 1000));
      }
    } catch (err) {
      results.push({ success: false, error: err.message, recipients: batch });
      failedTotal += batch.length;
    }
  }

  return {
    success: failedTotal === 0,
    sent: sentTotal,
    failed: failedTotal,
    results,
  };
}

async function sendBatchWithSes(job, batch, proxyUrl) {
  if (process.env.MAIL_TRANSPORT === "smtp") {
    return sendBatchWithSmtp(job, batch, proxyUrl);
  }
  const region = process.env.AWS_REGION || "us-east-1";
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;
  const ses = new SESClient({
    region,
    requestHandler: new NodeHttpHandler(agent ? { httpsAgent: agent } : {}),
  });
  const source = process.env.SES_FROM || job.smtpUsername;
  const params = {
    Destination: { ToAddresses: batch },
    Message: {
      Subject: { Data: job.subject },
      Body: {},
    },
    Source: source,
  };
  if (job.htmlBody) {
    params.Message.Body.Html = { Data: job.htmlBody };
    params.Message.Body.Text = { Data: job.textBody || stripHtml(job.htmlBody) };
  } else {
    params.Message.Body.Text = { Data: job.textBody || "" };
  }
  await ses.send(new SendEmailCommand(params));
}

function stripHtml(html) {
  return html.replace(/<[^>]+>/g, " ");
}

async function sendBatchWithSmtp(job, batch, proxyUrl) {
  const transportOptions = {
    host: job.smtpHost,
    port: job.smtpPort,
    secure: job.smtpPort === 465,
    auth: {
      user: job.smtpUsername,
      pass: job.smtpPassword,
    },
  };
  if (proxyUrl) {
    if (proxyUrl.startsWith("socks")) {
      transportOptions.agent = new SocksProxyAgent(proxyUrl);
    } else {
      transportOptions.proxy = proxyUrl;
    }
  }
  const transporter = nodemailer.createTransport(transportOptions);
  await transporter.sendMail({
    from: job.smtpUsername,
    to: batch,
    subject: job.subject,
    text: job.textBody,
    html: job.htmlBody,
  });
}

async function addMailbox(username, smtpUsername, smtpPassword) {
  const payload = await readJson(authFilePath, { users: [] });
  const user = payload.users.find((u) => u.username === username);
  if (!user) return;
  user.mailboxes = user.mailboxes || [];
  const now = new Date().toISOString();
  const existing = user.mailboxes.find((m) => m.smtpUsername === smtpUsername);
  if (existing) {
    existing.smtpPassword = smtpPassword;
    existing.updatedAt = now;
  } else {
    user.mailboxes.push({
      id: uuid(),
      label: smtpUsername,
      smtpUsername,
      smtpPassword,
      createdAt: now,
      updatedAt: now,
    });
  }
  await writeJson(authFilePath, payload);
}

// ---------- Static ----------
app.use(express.static(staticDir));

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT} (serving static from ${staticDir})`);
});
