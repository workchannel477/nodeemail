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
const staticDir = path.join(rootDir, "public");
const recipientsDir = path.join(dataDir, "job-recipients");

const authFilePath = path.join(dataDir, "auth.json");
const jobsFilePath = path.join(dataDir, "email-jobs.json");
const ipRotationFilePath = path.join(dataDir, "ip-rotation.json");
const rateLimitFilePath = path.join(dataDir, "rate-limit.json");
const smtpPoolFilePath = path.join(dataDir, "smtp-pool.json");

const app = express();
const PORT = process.env.PORT || 5000;

const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_MINUTE = parseInt(process.env.MAX_REQUESTS_PER_MINUTE || "60", 10);
const EMAIL_RATE_LIMIT = parseInt(process.env.MAX_EMAILS_PER_MINUTE || "10", 10);
const BATCH_SIZE_DEFAULT = parseInt(process.env.EMAIL_BATCH_SIZE || "50", 10);
const SMTP_ROTATE_AFTER_DEFAULT = 200;

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
  await fs.ensureDir(recipientsDir);
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
  if (!(await fs.pathExists(smtpPoolFilePath))) {
    await fs.writeJson(smtpPoolFilePath, {
      servers: [],
      currentIndex: 0,
      sentSinceRotation: 0,
      rotateAfter: SMTP_ROTATE_AFTER_DEFAULT,
      updatedAt: new Date().toISOString(),
    });
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

function recipientsFile(jobId) {
  return path.join(recipientsDir, `${jobId}.json`);
}

async function saveRecipients(jobId, recipients = []) {
  const list = normalizeRecipients(recipients);
  await fs.writeJson(recipientsFile(jobId), { recipients: list }, { spaces: 0 });
}

async function loadRecipients(job) {
  const collected = [];
  // Prefer stored file
  try {
    const data = await fs.readJson(recipientsFile(job.id));
    if (Array.isArray(data.recipients)) collected.push(...data.recipients);
  } catch (err) {
    // ignore
  }
  // Fallback to job payload (array or string)
  if (Array.isArray(job.recipients)) collected.push(...job.recipients);
  if (typeof job.recipients === "string") collected.push(...normalizeRecipients(job.recipients));
  return normalizeRecipients(collected);
}

async function loadRecipientsPreview(jobId, limit = 5, fallbackList = []) {
  try {
    const data = await fs.readJson(recipientsFile(jobId));
    const list = Array.isArray(data.recipients) ? data.recipients : [];
    return { recipientsPreview: list.slice(0, limit), recipientsCount: list.length };
  } catch (err) {
    const list = Array.isArray(fallbackList) ? fallbackList : normalizeRecipients(fallbackList);
    return { recipientsPreview: list.slice(0, limit), recipientsCount: list.length };
  }
}

const RECIPIENT_DELIMITER_REGEX = /[\s,;|:]+/;

function flattenRecipientInput(value) {
  if (value == null) return [];
  if (Array.isArray(value)) {
    return value.flatMap(flattenRecipientInput);
  }
  if (typeof value === "string") {
    return value.split(RECIPIENT_DELIMITER_REGEX);
  }
  return [value];
}

function normalizeRecipients(recipients = []) {
  return flattenRecipientInput(recipients)
    .map((r) => String(r).trim())
    .filter(Boolean);
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

function sanitizeSmtp(server) {
  if (!server) return server;
  const { password, ...rest } = server;
  return rest;
}

function normalizeRotateAfter(value) {
  const parsed = parseInt(value || SMTP_ROTATE_AFTER_DEFAULT, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : SMTP_ROTATE_AFTER_DEFAULT;
}

async function loadSmtpPool() {
  const payload = await readJson(smtpPoolFilePath, {
    servers: [],
    currentIndex: 0,
    sentSinceRotation: 0,
    rotateAfter: SMTP_ROTATE_AFTER_DEFAULT,
  });
  payload.servers = payload.servers || [];
  payload.currentIndex = parseInt(payload.currentIndex || "0", 10);
  payload.sentSinceRotation = Number(payload.sentSinceRotation) || 0;
  payload.rotateAfter = normalizeRotateAfter(payload.rotateAfter);
  if (payload.currentIndex >= payload.servers.length && payload.servers.length) {
    payload.currentIndex = 0;
    payload.sentSinceRotation = 0;
  }
  return payload;
}

async function saveSmtpPool(payload) {
  const normalizedServers = (payload.servers || []).map((server) => ({
    ...server,
    port: parseInt(server.port || "587", 10),
  }));
  const currentIndex = parseInt(payload.currentIndex || "0", 10);
  const normalized = {
    servers: normalizedServers,
    currentIndex,
    sentSinceRotation: Number(payload.sentSinceRotation) || 0,
    rotateAfter: normalizeRotateAfter(payload.rotateAfter),
    updatedAt: new Date().toISOString(),
  };
  if (normalized.currentIndex >= normalized.servers.length && normalized.servers.length) {
    normalized.currentIndex = 0;
    normalized.sentSinceRotation = 0;
  }
  await writeJson(smtpPoolFilePath, normalized);
  return normalized;
}

async function pickSmtpServer() {
  const pool = await loadSmtpPool();
  if (!pool.servers.length) {
    throw new Error("No SMTP servers configured. Ask an admin to add at least one SMTP account.");
  }
  const rotateAfter = normalizeRotateAfter(pool.rotateAfter);
  let mutated = false;
  if (pool.currentIndex >= pool.servers.length) {
    pool.currentIndex = 0;
    pool.sentSinceRotation = 0;
    mutated = true;
  }
  while (pool.servers.length && pool.sentSinceRotation >= rotateAfter) {
    pool.sentSinceRotation -= rotateAfter;
    pool.currentIndex = (pool.currentIndex + 1) % pool.servers.length;
    mutated = true;
  }
  if (mutated) {
    await saveSmtpPool(pool);
  }
  const server = { ...pool.servers[pool.currentIndex], __fromPool: true };
  return server;
}

async function recordSmtpUsage(sentCount = 0) {
  if (!sentCount) return;
  const pool = await loadSmtpPool();
  if (!pool.servers.length) return;
  pool.sentSinceRotation += sentCount;
  const rotateAfter = normalizeRotateAfter(pool.rotateAfter);
  while (pool.sentSinceRotation >= rotateAfter && pool.servers.length) {
    pool.sentSinceRotation -= rotateAfter;
    pool.currentIndex = (pool.currentIndex + 1) % pool.servers.length;
  }
  await saveSmtpPool(pool);
}

function formatFromAddress(name, email) {
  if (!email) return name || "";
  if (name) {
    return `${name} <${email}>`;
  }
  return email;
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

// ---------- Admin SMTP pool ----------
app.get("/admin/smtp", requireAuth, requireAdmin, async (_req, res) => {
  const pool = await loadSmtpPool();
  res.json({ ...pool, servers: (pool.servers || []).map((server) => sanitizeSmtp(server)) });
});

app.post("/admin/smtp", requireAuth, requireAdmin, async (req, res) => {
  const { label = "", from = "", host = "", port, username = "", password = "", rotateAfter } = req.body || {};
  if (!host || !username || !password) {
    return res.status(400).json({ message: "host, username, and password are required" });
  }
  const pool = await loadSmtpPool();
  const now = new Date().toISOString();
  const server = {
    id: uuid(),
    label: label || username,
    from: from || username,
    host: host.trim(),
    port: parseInt(port || "587", 10),
    username: username.trim(),
    password,
    createdAt: now,
    updatedAt: now,
  };
  pool.servers.push(server);
  if (rotateAfter !== undefined) {
    pool.rotateAfter = normalizeRotateAfter(rotateAfter);
    pool.sentSinceRotation = 0;
  }
  await saveSmtpPool(pool);
  res.status(201).json({ message: "SMTP added", server: sanitizeSmtp(server), rotateAfter: pool.rotateAfter });
});

app.put("/admin/smtp/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const updates = req.body || {};
  const pool = await loadSmtpPool();
  const server = (pool.servers || []).find((s) => s.id === id);
  if (!server) return res.status(404).json({ message: "SMTP server not found" });
  if (updates.label) server.label = updates.label;
  if (updates.from) server.from = updates.from;
  if (updates.host) server.host = updates.host;
  if (updates.port) server.port = parseInt(updates.port, 10) || server.port;
  if (updates.username) server.username = updates.username;
  if (updates.password) server.password = updates.password;
  if (updates.rotateAfter !== undefined) {
    pool.rotateAfter = normalizeRotateAfter(updates.rotateAfter);
    pool.sentSinceRotation = 0;
  }
  server.updatedAt = new Date().toISOString();
  await saveSmtpPool(pool);
  res.json({ message: "SMTP updated", server: sanitizeSmtp(server), rotateAfter: pool.rotateAfter });
});

app.delete("/admin/smtp/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const pool = await loadSmtpPool();
  const idx = (pool.servers || []).findIndex((s) => s.id === id);
  if (idx === -1) return res.status(404).json({ message: "SMTP server not found" });
  pool.servers.splice(idx, 1);
  if (pool.currentIndex >= pool.servers.length) {
    pool.currentIndex = 0;
    pool.sentSinceRotation = 0;
  }
  await saveSmtpPool(pool);
  res.json({ message: "SMTP server removed", remaining: pool.servers.length });
});

app.post("/admin/smtp/rotation", requireAuth, requireAdmin, async (req, res) => {
  const { rotateAfter } = req.body || {};
  const pool = await loadSmtpPool();
  pool.rotateAfter = normalizeRotateAfter(rotateAfter);
  pool.sentSinceRotation = 0;
  await saveSmtpPool(pool);
  res.json({ message: `Rotation set to every ${pool.rotateAfter} emails`, rotateAfter: pool.rotateAfter });
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
  const jobsWithPreview = await Promise.all(
    filtered.map(async (job) => {
      const { recipientsPreview, recipientsCount } = await loadRecipientsPreview(job.id, 5, job.recipients);
      return { ...job, recipientsPreview, recipientsCount };
    })
  );
  res.json(jobsWithPreview);
});

app.post("/api/jobs", requireAuth, async (req, res) => {
  const {
    subject = "",
    fromName = "",
    from = "", // legacy support; admin controls SMTP from email
    replyTo = "",
    textBody = "",
    htmlBody = "",
    recipients,
    batchSize,
    delayBetweenBatches = 2,
    maxRetries = 3,
  } = req.body || {};
  if (!subject || !fromName) {
    return res.status(400).json({ message: "fromName and subject are required" });
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
    fromName,
    from: from || undefined,
    replyTo: replyTo || undefined,
    textBody,
    htmlBody,
    recipientsCount: recipientList.length,
    recipientsPreview: recipientList.slice(0, 5),
    batchSize: parseInt(batchSize || BATCH_SIZE_DEFAULT, 10),
    delayBetweenBatches: parseInt(delayBetweenBatches, 10),
    maxRetries: parseInt(maxRetries, 10),
    status: "pending",
    createdAt: now,
    updatedAt: now,
  };
  payload.jobs.push(job);
  await writeJson(jobsFilePath, payload);
  await saveRecipients(job.id, recipientList);
  // Kick off sending immediately in the background
  setImmediate(() => {
    dispatchJob(job, payload).catch((err) => {
      console.error("Auto-dispatch failed for job", job.id, err.message);
    });
  });
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
  await fs.remove(recipientsFile(id));
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
  if (job.status === "sending") {
    return res.status(409).json({ message: "Job is already sending" });
  }
  try {
    const result = await dispatchJob(job, payload);
    res.json({ message: "Email dispatch complete", job, result });
  } catch (err) {
    const status = err.statusCode || 500;
    res.status(status).json({ message: err.message || "Failed to send email" });
  }
});

app.delete("/admin/jobs/:id/recipients", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  const { recipientsCount = 0 } = await loadRecipientsPreview(id);
  job.recipientsCount = 0;
  job.recipientsPreview = [];
  job.recipients = [];
  job.updatedAt = new Date().toISOString();
  await writeJson(jobsFilePath, payload);
  await fs.remove(recipientsFile(id));
  res.json({ message: "Recipient log cleared", removed: recipientsCount });
});

// ---------- Overview & health ----------
app.get("/admin/overview", requireAuth, requireAdmin, async (_req, res) => {
  const users = (await readJson(authFilePath, { users: [] })).users || [];
  const jobsRaw = (await readJson(jobsFilePath, { jobs: [] })).jobs || [];
  const jobs = await Promise.all(
    jobsRaw.map(async (job) => {
      const { recipientsPreview, recipientsCount } = await loadRecipientsPreview(job.id, 5, job.recipients);
      return { ...job, recipientsPreview, recipientsCount };
    })
  );
  const ipData = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  const rateLimits = await readJson(rateLimitFilePath, { limits: {} });
  const smtpPool = await loadSmtpPool();
  const sanitizedSmtpPool = { ...smtpPool, servers: (smtpPool.servers || []).map((s) => sanitizeSmtp(s)) };
  const stats = {
    totalUsers: users.length,
    activeUsers: users.filter((u) => (u.status || "active") === "active").length,
    suspendedUsers: users.filter((u) => (u.status || "active") === "suspended").length,
    totalJobs: jobs.length,
    pendingJobs: jobs.filter((j) => j.status === "pending").length,
    sendingJobs: jobs.filter((j) => j.status === "sending").length,
    sentJobs: jobs.filter((j) => j.status === "sent").length,
    failedJobs: jobs.filter((j) => j.status === "failed").length,
    sentEmails: jobs.reduce((acc, j) => acc + (j.sentCount || 0), 0),
    failedEmails: jobs.reduce((acc, j) => acc + (j.failedCount || 0), 0),
    proxyCount: (ipData.proxies || []).length,
    activeRateLimits: Object.keys(rateLimits.limits || {}).length,
    smtpServers: sanitizedSmtpPool.servers.length,
  };
  res.json({ users, jobs, ipRotation: ipData, rateLimits, smtpPool: sanitizedSmtpPool, stats });
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
  const recipients = await loadRecipients(job);
  if (!recipients.length) {
    throw new Error("This job does not have any recipients to send to.");
  }
  const batchSize = job.batchSize || BATCH_SIZE_DEFAULT;
  const results = [];
  let sentTotal = 0;
  let failedTotal = 0;

  for (let i = 0; i < recipients.length; i += batchSize) {
    const batch = recipients.slice(i, i + batchSize);
    try {
      const proxy = await getNextProxy();
      const useSes = process.env.MAIL_TRANSPORT === "ses" && !(await hasConfiguredSmtpPool());
      let smtpServer;
      if (useSes) {
        const sesResult = await sendBatchWithSes(job, batch, proxy);
        results.push({ ...sesResult, proxy, transport: "ses" });
        sentTotal += sesResult.sent;
        failedTotal += sesResult.failed;
      } else {
        smtpServer = await resolveSmtpServerForBatch(job);
        const smtpResult = await sendBatchWithSmtp(job, batch, smtpServer, proxy);
        if (smtpServer?.__fromPool) {
          await recordSmtpUsage(smtpResult.sent || batch.length);
        }
        results.push({ ...smtpResult, proxy });
        sentTotal += smtpResult.sent;
        failedTotal += smtpResult.failed;
      }
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
  const region = process.env.AWS_REGION || "us-east-1";
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;
  const ses = new SESClient({
    region,
    requestHandler: new NodeHttpHandler(agent ? { httpsAgent: agent } : {}),
  });
  const sourceEmail = process.env.SES_FROM || process.env.DEFAULT_FROM || job.from;
  if (!sourceEmail) {
    throw new Error("No FROM email configured. Set SES_FROM or DEFAULT_FROM.");
  }
  const source = formatFromAddress(job.fromName || job.from, sourceEmail);
  let sent = 0;
  let failed = 0;
  for (const recipient of batch) {
    const params = {
      Destination: { ToAddresses: [recipient] },
      Message: {
        Subject: { Data: job.subject },
        Body: {},
      },
      Source: source,
    };
    if (job.replyTo) {
      params.ReplyToAddresses = [job.replyTo];
    }
    if (job.htmlBody) {
      params.Message.Body.Html = { Data: job.htmlBody };
      params.Message.Body.Text = { Data: job.textBody || stripHtml(job.htmlBody) };
    } else {
      params.Message.Body.Text = { Data: job.textBody || "" };
    }
    try {
      await ses.send(new SendEmailCommand(params));
      sent += 1;
    } catch (err) {
      failed += 1;
    }
  }
  return { success: failed === 0, sent, failed, recipients: batch };
}

function stripHtml(html) {
  return html.replace(/<[^>]+>/g, " ");
}

function buildSendSummary(result = {}) {
  return {
    sent: result.sent || 0,
    failed: result.failed || 0,
    batches: Array.isArray(result.results) ? result.results.length : 0,
  };
}

async function dispatchJob(job, payload, { skipRateLimit = false } = {}) {
  job.status = "sending";
  job.updatedAt = new Date().toISOString();
  await writeJson(jobsFilePath, payload);

  if (!skipRateLimit) {
    const allowed = await checkEmailRateLimit(job.owner);
    if (!allowed) {
      const errMsg = `Email rate limit exceeded. Maximum ${EMAIL_RATE_LIMIT} emails per minute.`;
      job.status = "failed";
      job.error = errMsg;
      job.updatedAt = new Date().toISOString();
      await writeJson(jobsFilePath, payload);
      const rateErr = new Error(errMsg);
      rateErr.statusCode = 429;
      throw rateErr;
    }
  }

  try {
    const result = await sendEmailJob(job);
    const summary = buildSendSummary(result);
    job.status = result.success ? "sent" : "failed";
    job.lastSentAt = new Date().toISOString();
    job.lastResult = summary;
    job.sentCount = summary.sent;
    job.failedCount = summary.failed;
    delete job.error;
    job.updatedAt = new Date().toISOString();
    await writeJson(jobsFilePath, payload);
    return result;
  } catch (err) {
    job.status = "failed";
    job.error = err.message;
    job.updatedAt = new Date().toISOString();
    await writeJson(jobsFilePath, payload);
    throw err;
  }
}

async function resolveSmtpServerForBatch(job) {
  try {
    const server = await pickSmtpServer();
    return server;
  } catch (err) {
    if (job.smtpUsername && job.smtpPassword) {
      // Legacy support for jobs created before SMTP pool existed
      return {
        id: "legacy",
        label: job.smtpUsername,
        from: job.from || job.replyTo || job.smtpUsername,
        host: job.smtpHost || process.env.DEFAULT_SMTP_HOST || "email-smtp.us-east-1.amazonaws.com",
        port: parseInt(job.smtpPort || process.env.DEFAULT_SMTP_PORT || "587", 10),
        username: job.smtpUsername,
        password: job.smtpPassword,
      };
    }
    throw err;
  }
}

async function hasConfiguredSmtpPool() {
  const pool = await loadSmtpPool();
  return (pool.servers || []).length > 0;
}

async function sendBatchWithSmtp(job, batch, smtpServer, proxyUrl) {
  const port = parseInt(smtpServer.port || "587", 10);
  const fromEmail = smtpServer.from || smtpServer.username;
  const fromAddress = formatFromAddress(job.fromName || job.from || smtpServer.label, fromEmail);
  const replyToAddress = job.replyTo
    ? formatFromAddress(undefined, job.replyTo)
    : formatFromAddress(job.fromName || job.from, fromEmail);
  const transportOptions = {
    host: smtpServer.host,
    port,
    secure: port === 465,
    auth: {
      user: smtpServer.username,
      pass: smtpServer.password,
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
  let sent = 0;
  let failed = 0;
  for (const recipient of batch) {
    try {
      await transporter.sendMail({
        from: fromAddress,
        replyTo: replyToAddress,
        to: recipient,
        subject: job.subject,
        text: job.textBody || (job.htmlBody ? stripHtml(job.htmlBody) : ""),
        html: job.htmlBody,
      });
      sent += 1;
    } catch (err) {
      failed += 1;
    }
  }
  return {
    success: failed === 0,
    sent,
    failed,
    recipients: batch,
    smtpId: smtpServer.id || smtpServer.username,
    smtpLabel: smtpServer.label,
    transport: "smtp",
  };
}

// ---------- Static ----------
app.use(express.static(staticDir));

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT} (serving static from ${staticDir})`);
});
