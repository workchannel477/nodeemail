import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs-extra";
import { fileURLToPath } from "url";
import { v4 as uuid } from "uuid";
import { SESClient, SendRawEmailCommand } from "@aws-sdk/client-ses";
import { NodeHttpHandler } from "@aws-sdk/node-http-handler";
import { HttpsProxyAgent } from "https-proxy-agent";
import nodemailer from "nodemailer";
import { SocksProxyAgent } from "socks-proxy-agent";
import { createHash } from "crypto";
import { execSync } from "child_process";
import FormData from "form-data";
import https from "https";
import dotenv from "dotenv";

dotenv.config();

const ENV_ALIASES = {
  PORT: ["APP_PORT", "PORT"],
  SECRET_KEY: ["APP_SIGMA", "SECRET_KEY"],
  SESSION_TIMEOUT: ["APP_TAU", "SESSION_TIMEOUT"],
  MAX_REQUESTS_PER_MINUTE: ["APP_REQ_RATE", "MAX_REQUESTS_PER_MINUTE"],
  MAX_EMAILS_PER_MINUTE: ["APP_MAIL_CAP", "MAX_EMAILS_PER_MINUTE"],
  EMAIL_BATCH_SIZE: ["APP_BATCH", "EMAIL_BATCH_SIZE"],
  SMTP_CONNECTION_TIMEOUT_MS: ["APP_SMTP_CONN", "SMTP_CONNECTION_TIMEOUT_MS"],
  SMTP_SOCKET_TIMEOUT_MS: ["APP_SMTP_SOCKET", "SMTP_SOCKET_TIMEOUT_MS"],
  MAIL_TRANSPORT: ["APP_MAIL_TRANSPORT", "MAIL_TRANSPORT"],
  ZOHO_DOMAIN: ["APP_ZOHO_DOMAIN", "ZOHO_DOMAIN"],
  ZOHO_CLIENT_ID: ["APP_ZOHO_CLIENT_ID", "ZOHO_CLIENT_ID"],
  ZOHO_CLIENT_SECRET: ["APP_ZOHO_CLIENT_SECRET", "ZOHO_CLIENT_SECRET"],
  ZOHO_REFRESH_TOKEN: ["APP_ZOHO_REFRESH", "ZOHO_REFRESH_TOKEN"],
  ZOHO_FROM_ADDRESS: ["APP_ZOHO_FROM", "ZOHO_FROM_ADDRESS"],
  ZOHO_ACCOUNT_ID: ["APP_ZOHO_ACCOUNT", "ZOHO_ACCOUNT_ID"],
  ZOHO_ACCOUNTS_HOST: ["APP_ZOHO_AUTH", "ZOHO_ACCOUNTS_HOST"],
  ZOHO_MAIL_HOST: ["APP_ZOHO_MAIL", "ZOHO_MAIL_HOST"],
  SES_FROM: ["APP_SES_FROM", "SES_FROM"],
  DEFAULT_FROM: ["APP_DEFAULT_FROM", "DEFAULT_FROM"],
  AWS_REGION: ["APP_AWS_REGION", "AWS_REGION"],
  AWS_ACCESS_KEY_ID: ["APP_AWS_ACCESS", "AWS_ACCESS_KEY_ID"],
  AWS_SECRET_ACCESS_KEY: ["APP_AWS_SECRET", "AWS_SECRET_ACCESS_KEY"],
  DEFAULT_SMTP_HOST: ["APP_SMTP_HOST", "DEFAULT_SMTP_HOST"],
  DEFAULT_SMTP_PORT: ["APP_SMTP_PORT", "DEFAULT_SMTP_PORT"],
  DATA_OBFUSCATION_KEY: ["APP_DATA_MASK", "DATA_OBFUSCATION_KEY"],
};

function decodeSecretValue(raw) {
  if (raw == null) return raw;
  if (raw.startsWith("enc:")) {
    const payload = raw.slice(4);
    try {
      return Buffer.from(payload, "base64").toString("utf8");
    } catch (err) {
      return raw;
    }
  }
  return raw;
}

function envValue(name, fallback, { secret = false } = {}) {
  const keys = ENV_ALIASES[name] || [name];
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(process.env, key)) {
      const raw = process.env[key];
      const value = secret ? decodeSecretValue(raw) : raw;
      return value;
    }
  }
  return fallback;
}

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
const mailProvidersFilePath = path.join(dataDir, "mail-providers.json");
const activityLogPath = path.join(dataDir, "activity-log.json");

const app = express();
const PORT = parseInt(envValue("PORT", "5001"), 10);

const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_MINUTE = parseInt(envValue("MAX_REQUESTS_PER_MINUTE", "60"), 10);
const EMAIL_RATE_LIMIT = parseInt(envValue("MAX_EMAILS_PER_MINUTE", "10"), 10);
const BATCH_SIZE_DEFAULT = parseInt(envValue("EMAIL_BATCH_SIZE", "50"), 10);
const SMTP_ROTATE_AFTER_DEFAULT = 200;
const SMTP_CONNECTION_TIMEOUT_MS = parseInt(envValue("SMTP_CONNECTION_TIMEOUT_MS", "15000"), 10);
const SMTP_SOCKET_TIMEOUT_MS = parseInt(envValue("SMTP_SOCKET_TIMEOUT_MS", "20000"), 10);
const DATA_SYNC_DEFAULT_MESSAGE = "chore: sync data folder";
const MAIL_TRANSPORT = (envValue("MAIL_TRANSPORT", "smtp") || "smtp").toLowerCase();
const ZOHO_DOMAIN = envValue("ZOHO_DOMAIN", "zoho.com");
const ZOHO_CLIENT_ID = envValue("ZOHO_CLIENT_ID", "", { secret: true }) || "";
const ZOHO_CLIENT_SECRET = envValue("ZOHO_CLIENT_SECRET", "", { secret: true }) || "";
const ZOHO_REFRESH_TOKEN = envValue("ZOHO_REFRESH_TOKEN", "", { secret: true }) || "";
const DEFAULT_FROM_ADDRESS = envValue("DEFAULT_FROM", undefined, { secret: true });
const SES_FROM_ADDRESS = envValue("SES_FROM", DEFAULT_FROM_ADDRESS, { secret: true });
const ZOHO_FROM_ADDRESS = envValue("ZOHO_FROM_ADDRESS", SES_FROM_ADDRESS, { secret: true });
const ZOHO_ACCOUNT_ID = envValue("ZOHO_ACCOUNT_ID", "", { secret: true }) || "";
const ZOHO_ACCOUNTS_HOST = envValue("ZOHO_ACCOUNTS_HOST", `accounts.${ZOHO_DOMAIN}`);
const ZOHO_MAIL_HOST = envValue("ZOHO_MAIL_HOST", `mail.${ZOHO_DOMAIN}`);
const AWS_REGION = envValue("AWS_REGION", "us-east-1");
const AWS_ACCESS_KEY_ID = envValue("AWS_ACCESS_KEY_ID", "", { secret: true });
const AWS_SECRET_ACCESS_KEY = envValue("AWS_SECRET_ACCESS_KEY", "", { secret: true });
const DEFAULT_SMTP_HOST = envValue("DEFAULT_SMTP_HOST", "email-smtp.us-east-1.amazonaws.com");
const DEFAULT_SMTP_PORT = parseInt(envValue("DEFAULT_SMTP_PORT", "587"), 10);
const DATA_OBFUSCATION_KEY = envValue("DATA_OBFUSCATION_KEY", "nodeemail", { secret: true }) || "nodeemail";
const SESSION_TIMEOUT_SECONDS = parseInt(envValue("SESSION_TIMEOUT", "3600"), 10);

if (AWS_ACCESS_KEY_ID) process.env.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID;
if (AWS_SECRET_ACCESS_KEY) process.env.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY;

const sessions = new Map();
const apiRate = new Map();
const zohoTokenCache = new Map();

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
    await writeJson(authFilePath, {
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
    await writeJson(jobsFilePath, { jobs: [] });
  }
  if (!(await fs.pathExists(ipRotationFilePath))) {
    await writeJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  }
  if (!(await fs.pathExists(rateLimitFilePath))) {
    await writeJson(rateLimitFilePath, { limits: {} });
  }
  if (!(await fs.pathExists(smtpPoolFilePath))) {
    await writeJson(smtpPoolFilePath, {
      servers: [],
      currentIndex: 0,
      sentSinceRotation: 0,
      rotateAfter: SMTP_ROTATE_AFTER_DEFAULT,
      updatedAt: new Date().toISOString(),
    });
  }
  if (!(await fs.pathExists(activityLogPath))) {
    await writeJson(activityLogPath, { entries: [] });
  }
  if (!(await fs.pathExists(mailProvidersFilePath))) {
    await writeJson(mailProvidersFilePath, { providers: [], rotationIndex: 0 });
  }
}

const DATA_KEY_BUFFER = Buffer.from(DATA_OBFUSCATION_KEY || "nodeemail");

function xorBuffer(buffer, keyBuffer) {
  const out = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i += 1) {
    out[i] = buffer[i] ^ keyBuffer[i % keyBuffer.length];
  }
  return out;
}

function obfuscatePayload(value) {
  const json = JSON.stringify(value);
  const jsonBuffer = Buffer.from(json, "utf8");
  const scrambled = xorBuffer(jsonBuffer, DATA_KEY_BUFFER.length ? DATA_KEY_BUFFER : Buffer.from("nodeemail"));
  return scrambled.toString("base64");
}

function revealPayload(encoded) {
  const buffer = Buffer.from(encoded, "base64");
  const plain = xorBuffer(buffer, DATA_KEY_BUFFER.length ? DATA_KEY_BUFFER : Buffer.from("nodeemail"));
  return JSON.parse(plain.toString("utf8"));
}

function wrapObfuscated(value) {
  return {
    __obf: true,
    __v: 1,
    __data: obfuscatePayload(value),
  };
}

function unwrapObfuscated(parsed) {
  if (parsed && parsed.__obf && parsed.__data) {
    try {
      return revealPayload(parsed.__data);
    } catch (err) {
      return parsed;
    }
  }
  return parsed;
}

async function readJson(filePath, fallback = {}) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    if (!raw.trim()) return fallback;
    const parsed = JSON.parse(raw);
    const unwrapped = unwrapObfuscated(parsed);
    return unwrapped;
  } catch (err) {
    if (err.code === "ENOENT") {
      await writeJson(filePath, fallback);
      return fallback;
    }
    throw err;
  }
}

async function writeJson(filePath, value) {
  const wrapped = wrapObfuscated(value);
  await fs.outputFile(filePath, JSON.stringify(wrapped));
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
  await writeJson(recipientsFile(jobId), { recipients: list });
}

async function loadRecipients(job) {
  const collected = [];
  // Prefer stored file
  try {
    const data = await readJson(recipientsFile(job.id), { recipients: [] });
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
    const data = await readJson(recipientsFile(jobId), { recipients: [] });
    const list = Array.isArray(data.recipients) ? data.recipients : [];
    return { recipientsPreview: list.slice(0, limit), recipientsCount: list.length };
  } catch (err) {
    const list = Array.isArray(fallbackList) ? fallbackList : normalizeRecipients(fallbackList);
    return { recipientsPreview: list.slice(0, limit), recipientsCount: list.length };
  }
}

const RECIPIENT_DELIMITER_REGEX = /[\s,;|:]+/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

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

function attemptRecipientRepair(rawValue) {
  const input = (rawValue || "").trim().toLowerCase();
  if (!input || input.includes("@")) return input;
  const compact = input.replace(/\s+/g, "");
  if (!compact.includes(".")) return input;
  const parts = compact.split(".").filter(Boolean);
  if (parts.length < 3) return input;
  const tld = parts.pop();
  const domainLabel = parts.pop();
  if (!domainLabel || !tld) return input;
  const local = parts.join(".");
  if (!local) return input;
  const domain = `${domainLabel}.${tld}`;
  const candidate = `${local}@${domain}`;
  if (!EMAIL_PATTERN.test(candidate)) return input;
  return candidate;
}

function normalizeRecipients(recipients = []) {
  return flattenRecipientInput(recipients)
    .map((r) => attemptRecipientRepair(String(r).trim().toLowerCase()))
    .filter(Boolean);
}

function isValidEmail(recipient) {
  return EMAIL_PATTERN.test(recipient);
}

function splitRecipientList(list = []) {
  const valid = [];
  const invalid = [];
  for (const entry of list) {
    if (isValidEmail(entry)) valid.push(entry);
    else invalid.push(entry);
  }
  return { valid, invalid };
}

async function readActivityLog() {
  return readJson(activityLogPath, { entries: [] });
}

async function appendActivityLog(entry) {
  const payload = await readActivityLog();
  payload.entries = payload.entries || [];
  payload.entries.unshift(entry);
  if (payload.entries.length > 200) {
    payload.entries = payload.entries.slice(0, 200);
  }
  await writeJson(activityLogPath, payload);
}

function extractResultError(result = {}) {
  if (Array.isArray(result.results)) {
    for (const batch of result.results) {
      if (batch && Array.isArray(batch.errorDetails) && batch.errorDetails.length) {
        const detail = batch.errorDetails[0] || {};
        if (detail.code) {
          return `SMTP error ${detail.code}: ${detail.message || detail.response || "Unknown error"}`;
        }
        if (detail.message || detail.response) {
          return detail.message || detail.response;
        }
      }
      if (batch && batch.error) {
        return batch.error;
      }
      if (batch && batch.failed > 0) {
        return `Failed to send to ${batch.failed} recipient(s)`;
      }
    }
  }
  return null;
}

function summarizeSend(job, result) {
  const total = job.recipientsCount || (result ? (result.sent || 0) + (result.failed || 0) : 0);
  return `Sent ${result?.sent || 0}/${total || 0} emails`;
}

async function recordActivity(job, result, errorMessage, transportMeta) {
  const summaryMessage = errorMessage || extractResultError(result) || summarizeSend(job, result);
  const flattenedDetails = Array.isArray(result?.results)
    ? result.results.flatMap((batch) => batch.errorDetails || []).slice(0, 20)
    : [];
  const transportDetails = transportMeta || summarizeTransportDetails(result);
  const entryTransport = job.lastTransport || transportDetails.lastTransport || determineJobTransport(job);
  const entry = {
    id: uuid(),
    jobId: job.id,
    owner: job.owner,
    subject: job.subject,
    status: errorMessage ? "failed" : result?.success ? "sent" : "failed",
    sent: result?.sent || 0,
    failed: result?.failed || 0,
    recipientsCount: job.recipientsCount || 0,
    message: summaryMessage,
    timestamp: new Date().toISOString(),
    errorDetails: flattenedDetails,
    transport: entryTransport,
  };
  if (transportDetails?.transports?.length) {
    entry.transports = transportDetails.transports.slice(-20);
  }
  if (transportDetails?.lastProvider) {
    entry.provider = transportDetails.lastProvider;
  }
  await appendActivityLog(entry);
}

function normalizeProviderUsage(usage = {}) {
  return {
    dayKey: usage.dayKey || new Date().toISOString().slice(0, 10),
    sentToday: Number(usage.sentToday) || 0,
    minuteWindow: Array.isArray(usage.minuteWindow)
      ? usage.minuteWindow.map((ts) => Number(ts)).filter((ts) => Number.isFinite(ts))
      : [],
  };
}

function normalizeMailProvider(provider = {}) {
  return {
    id: provider.id || uuid(),
    name: provider.name || "Provider",
    type: (provider.type || "smtp").toLowerCase(),
    enabled: provider.enabled !== false,
    quotaPerMinute: Number(provider.quotaPerMinute) || 60,
    quotaPerDay: Number(provider.quotaPerDay) || 1000,
    config: provider.config || {},
    usage: normalizeProviderUsage(provider.usage),
    createdAt: provider.createdAt || new Date().toISOString(),
    updatedAt: provider.updatedAt || new Date().toISOString(),
  };
}

async function loadMailProviderPool() {
  const pool = await readJson(mailProvidersFilePath, { providers: [], rotationIndex: 0 });
  pool.providers = Array.isArray(pool.providers)
    ? pool.providers.map(normalizeMailProvider)
    : [];
  pool.rotationIndex = Number(pool.rotationIndex) || 0;
  return pool;
}

async function saveMailProviderPool(pool) {
  pool.providers = (pool.providers || []).map(normalizeMailProvider);
  pool.rotationIndex = pool.providers.length
    ? Math.max(0, Math.min(Number(pool.rotationIndex) || 0, pool.providers.length - 1))
    : 0;
  await writeJson(mailProvidersFilePath, pool);
}

function ensureProviderUsage(provider, now = Date.now()) {
  let mutated = false;
  provider.usage = normalizeProviderUsage(provider.usage);
  const dayKey = new Date(now).toISOString().slice(0, 10);
  if (provider.usage.dayKey !== dayKey) {
    provider.usage.dayKey = dayKey;
    provider.usage.sentToday = 0;
    provider.usage.minuteWindow = [];
    mutated = true;
  }
  const filtered = provider.usage.minuteWindow.filter((ts) => now - ts < 60_000);
  if (filtered.length !== provider.usage.minuteWindow.length) {
    provider.usage.minuteWindow = filtered;
    mutated = true;
  }
  return mutated;
}

function providerCanSend(provider, batchSize, now = Date.now()) {
  ensureProviderUsage(provider, now);
  if (provider.quotaPerDay > 0 && provider.usage.sentToday + batchSize > provider.quotaPerDay) {
    return false;
  }
  if (
    provider.quotaPerMinute > 0 &&
    provider.usage.minuteWindow.length + batchSize > provider.quotaPerMinute
  ) {
    return false;
  }
  return true;
}

async function incrementProviderUsage(providerId, increment) {
  if (!providerId || !increment) return;
  const pool = await loadMailProviderPool();
  const provider = pool.providers.find((p) => p.id === providerId);
  if (!provider) return;
  const now = Date.now();
  ensureProviderUsage(provider, now);
  for (let i = 0; i < increment; i += 1) {
    provider.usage.minuteWindow.push(now);
  }
  provider.usage.sentToday += increment;
  provider.updatedAt = new Date().toISOString();
  await saveMailProviderPool(pool);
}

async function selectMailProvider(batchSize, excludeIds = []) {
  const pool = await loadMailProviderPool();
  const { providers } = pool;
  if (!providers.length) return null;
  const start = pool.rotationIndex || 0;
  const now = Date.now();
  let mutated = false;
  for (let i = 0; i < providers.length; i += 1) {
    const idx = (start + i) % providers.length;
    const provider = providers[idx];
    if (!provider || !provider.enabled || excludeIds.includes(provider.id)) continue;
    if (ensureProviderUsage(provider, now)) mutated = true;
    if (!providerCanSend(provider, batchSize, now)) continue;
    pool.rotationIndex = (idx + 1) % providers.length;
    mutated = true;
    if (mutated) {
      await saveMailProviderPool(pool);
    }
    return provider;
  }
  if (mutated) {
    await saveMailProviderPool(pool);
  }
  return null;
}

async function dispatchWithProvider(provider, job, batch) {
  const type = provider.type || "smtp";
  const config = provider.config || {};
  if (type === "zoho") {
    return sendBatchWithZoho(job, batch, config);
  }
  if (type === "ses") {
    const proxy = config.proxy || null;
    return sendBatchWithSes(job, batch, proxy, config);
  }
  if (type === "smtp") {
    const smtpConfig = {
      ...config,
      label: config.label || provider.name,
      from: config.from || config.fromAddress,
    };
    return sendBatchWithSmtp(job, batch, smtpConfig, config.proxy);
  }
  return {
    success: false,
    sent: 0,
    failed: batch.length,
    recipients: batch,
    transport: type,
    error: `Unsupported provider type ${type}`,
    errorDetails: [{ message: `Unsupported provider type ${type}` }],
  };
}

async function sendBatchUsingProviders(job, batch) {
  const tried = [];
  const errors = [];
  while (true) {
    const provider = await selectMailProvider(batch.length, tried);
    if (!provider) {
      if (errors.length) throw new Error(errors.join(" | "));
      return null;
    }
    const result = await dispatchWithProvider(provider, job, batch);
    if (result.success) {
      await incrementProviderUsage(provider.id, result.sent);
      return { ...result, provider: { id: provider.id, name: provider.name, type: provider.type } };
    }
    errors.push(`${provider.name || provider.id}: ${result.error || "Failed to send"}`);
    tried.push(provider.id);
  }
}

async function hasEnabledMailProviders() {
  const pool = await loadMailProviderPool();
  return pool.providers.some((p) => p.enabled);
}

function validateProviderConfig(type, config = {}) {
  if (type === "zoho") {
    const required = ["accountId", "clientId", "clientSecret", "refreshToken", "fromAddress"];
    const missing = required.filter((key) => !config[key]);
    if (missing.length) return `Zoho provider missing: ${missing.join(", ")}`;
    return null;
  }
  if (type === "ses") {
    const required = ["region", "accessKeyId", "secretAccessKey", "fromAddress"];
    const missing = required.filter((key) => !config[key]);
    if (missing.length) return `SES provider missing: ${missing.join(", ")}`;
    return null;
  }
  if (type === "smtp") {
    const required = ["host", "port", "username", "password", "fromAddress"];
    const missing = required.filter((key) => !config[key]);
    if (missing.length) return `SMTP provider missing: ${missing.join(", ")}`;
    return null;
  }
  return `Unsupported provider type ${type}`;
}

function sanitizeProviderPayload(payload = {}, existing = {}) {
  const provider = { ...existing };
  if (payload.name !== undefined) provider.name = String(payload.name || "").trim();
  if (payload.type !== undefined) provider.type = String(payload.type || "smtp").toLowerCase();
  if (payload.enabled !== undefined) provider.enabled = Boolean(payload.enabled);
  if (payload.quotaPerMinute !== undefined) {
    provider.quotaPerMinute = Math.max(0, parseInt(payload.quotaPerMinute, 10) || 0);
  }
  if (payload.quotaPerDay !== undefined) {
    provider.quotaPerDay = Math.max(0, parseInt(payload.quotaPerDay, 10) || 0);
  }
  if (payload.config !== undefined) {
    provider.config =
      payload.config && typeof payload.config === "object" ? payload.config : provider.config || {};
  }
  provider.updatedAt = new Date().toISOString();
  return normalizeMailProvider(provider);
}

async function getZohoAccessToken(config = {}) {
  const clientId = config.clientId || ZOHO_CLIENT_ID;
  const clientSecret = config.clientSecret || ZOHO_CLIENT_SECRET;
  const refreshToken = config.refreshToken || ZOHO_REFRESH_TOKEN;
  const accountsHost = config.accountsHost || config.accounts_host || ZOHO_ACCOUNTS_HOST;
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error("Zoho Mail API credentials are not configured");
  }
  const cacheKey = `${clientId}:${refreshToken}:${accountsHost}`;
  const cached = zohoTokenCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt - 60_000) {
    return cached.token;
  }
  const params = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "refresh_token",
  });
  const response = await fetch(`https://${accountsHost}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    const errMsg = data.error || data.error_description || response.statusText;
    throw new Error(`Zoho token error: ${errMsg}`);
  }
  const expiresIn = Number(data.expires_in) || 3600;
  zohoTokenCache.set(cacheKey, { token: data.access_token, expiresAt: Date.now() + expiresIn * 1000 });
  return data.access_token;
}

function normalizeJobAttachments(job) {
  const list = Array.isArray(job?.attachments) ? job.attachments : [];
  return list
    .map((att) => {
      if (!att || !att.filename) return null;
      let buffer = null;
      if (typeof att.content === "string") {
        const encoding = att.encoding || "base64";
        try {
          buffer = Buffer.from(att.content, encoding);
        } catch (err) {
          return null;
        }
      } else if (att.buffer && Buffer.isBuffer(att.buffer)) {
        buffer = att.buffer;
      }
      if (!buffer) return null;
      return {
        filename: att.filename,
        contentType: att.contentType || att.mimetype || "application/octet-stream",
        buffer,
      };
    })
    .filter(Boolean);
}

function normalizeAttachmentPayloadForStorage(attachments) {
  if (!Array.isArray(attachments)) return [];
  return attachments
    .map((att) => {
      if (!att || !att.filename || !att.content) return null;
      const encoding = (att.encoding || "base64").toLowerCase();
      return {
        filename: String(att.filename),
        content: String(att.content),
        encoding,
        contentType: att.contentType || att.mimetype || "application/octet-stream",
      };
    })
    .filter(Boolean);
}

function determineJobTransport(job = {}) {
  return (
    job.lastTransport ||
    job.transportHint ||
    (job.smtpUsername || job.smtpPassword || job.smtpHost ? "smtp" : MAIL_TRANSPORT)
  );
}

function storedJobTransport(job = {}) {
  return job.lastTransport || job.transportHint || null;
}

function summarizeTransportDetails(result) {
  const transports = [];
  const providers = [];
  if (Array.isArray(result?.results)) {
    for (const batch of result.results) {
      if (batch?.transport) transports.push(batch.transport);
      if (batch?.provider) providers.push(batch.provider);
    }
  }
  return {
    transports,
    providers,
    lastTransport: transports.length ? transports[transports.length - 1] : null,
    lastProvider: providers.length ? providers[providers.length - 1] : null,
  };
}

function mergeTransportHistory(existing = [], additions = []) {
  const merged = [...(existing || []), ...(additions || [])].slice(-50);
  return merged;
}

function resetJobForReplay(job) {
  job.status = "pending";
  job.sentCount = 0;
  job.failedCount = 0;
  delete job.error;
  delete job.lastResult;
  delete job.lastSentAt;
  job.updatedAt = new Date().toISOString();
}

async function replayExistingJob(job, payload, options = {}) {
  resetJobForReplay(job);
  const replayOptions = {
    skipRateLimit: options.skipRateLimit === undefined ? false : options.skipRateLimit,
  };
  return dispatchJob(job, payload, replayOptions);
}

function buildZohoForm(job, recipients, config = {}) {
  const accountId = config.accountId || ZOHO_ACCOUNT_ID;
  if (!accountId) {
    throw new Error("ZOHO_ACCOUNT_ID is not configured");
  }
  const fromAddress = job.from || config.fromAddress || ZOHO_FROM_ADDRESS;
  if (!fromAddress) {
    throw new Error("No from address configured for Zoho transport");
  }
  const content = job.htmlBody || job.textBody || "";
  const form = new FormData();
  form.append("fromAddress", fromAddress);
  form.append("toAddress", recipients.join(","));
  if (job.replyTo) form.append("replyToAddress", job.replyTo);
  form.append("subject", job.subject || "");
  form.append("content", content);
  form.append("mailFormat", job.htmlBody ? "html" : "text");
  const attachments = normalizeJobAttachments(job);
  attachments.forEach((att) => {
    form.append("attachments", att.buffer, {
      filename: att.filename,
      contentType: att.contentType,
    });
  });
  return form;
}

async function submitZohoForm(form, config = {}) {
  const token = await getZohoAccessToken(config);
  const headers = {
    Authorization: `Zoho-oauthtoken ${token}`,
    Accept: "application/json",
    ...form.getHeaders(),
  };
  const mailHost = config.mailHost || config.mail_host || ZOHO_MAIL_HOST;
  const accountId = config.accountId || ZOHO_ACCOUNT_ID;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: "POST",
        host: mailHost,
        path: `/api/accounts/${accountId}/messages`,
        headers,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          let parsed = {};
          try {
            parsed = data ? JSON.parse(data) : {};
          } catch (err) {
            parsed = { message: data };
          }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(
              new Error(
                `Zoho API ${res.statusCode}: ${parsed.message || parsed.data || data || res.statusMessage}`
              )
            );
          }
        });
      }
    );
    req.on("error", reject);
    form.pipe(req);
  });
}

async function sendBatchWithZoho(job, batch, config = {}) {
  try {
    const form = buildZohoForm(job, batch, config);
    await submitZohoForm(form, config);
    return {
      success: true,
      sent: batch.length,
      failed: 0,
      recipients: batch,
      transport: "zoho",
      errorDetails: [],
    };
  } catch (err) {
    console.error("Zoho send failure:", err.message);
    return {
      success: false,
      sent: 0,
      failed: batch.length,
      recipients: batch,
      transport: "zoho",
      error: err.message,
      errorDetails: [{ message: err.message }],
    };
  }
}

function runGitCommand(command, logs, { allowFailure = false } = {}) {
  const entry = { command };
  try {
    const stdout = execSync(command, {
      cwd: rootDir,
      stdio: ["ignore", "pipe", "pipe"],
    });
    entry.stdout = stdout.toString().trim();
    logs.push(entry);
    return entry.stdout || "";
  } catch (err) {
    entry.stdout = err.stdout ? err.stdout.toString().trim() : "";
    entry.stderr = err.stderr ? err.stderr.toString().trim() : err.message;
    entry.failed = true;
    logs.push(entry);
    if (allowFailure) {
      return entry.stdout || entry.stderr || "";
    }
    const error = new Error(entry.stderr || entry.stdout || err.message);
    error.gitLogs = logs;
    throw error;
  }
}

function syncDataRepo({ message, push }) {
  const logs = [];
  const statusOutput = runGitCommand("git status --porcelain data", logs, { allowFailure: true });
  if (!statusOutput.trim()) {
    return { changed: false, pushed: false, logs };
  }
  runGitCommand("git add data", logs);
  const commitMessage = String(message || "").trim() || DATA_SYNC_DEFAULT_MESSAGE;
  runGitCommand(`git commit -m ${JSON.stringify(commitMessage)}`, logs);
  let pushed = false;
  if (push) {
    runGitCommand("git push", logs);
    pushed = true;
  }
  return { changed: true, pushed, commitMessage, logs };
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
    expiresAt: Date.now() + SESSION_TIMEOUT_SECONDS * 1000,
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

app.post("/admin/data-sync", requireAuth, requireAdmin, async (req, res) => {
  const { message = "", push = true } = req.body || {};
  try {
    const result = syncDataRepo({ message, push: push !== false });
    const text = result.changed
      ? `Data committed${result.pushed ? " and pushed" : ""}.`
      : "No changes detected.";
    res.json({ message: text, ...result });
  } catch (err) {
    const logs = err.gitLogs || [];
    res.status(500).json({ message: err.message || "Failed to sync data", logs });
  }
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
  jobsWithPreview.sort((a, b) => {
    const dateA = new Date(a.updatedAt || a.createdAt || 0).getTime();
    const dateB = new Date(b.updatedAt || b.createdAt || 0).getTime();
    return dateB - dateA;
  });
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
    attachments = [],
    batchSize,
    delayBetweenBatches = 2,
    maxRetries = 3,
  } = req.body || {};
  if (!subject || !fromName) {
    return res.status(400).json({ message: "fromName and subject are required" });
  }
  const recipientListRaw = normalizeRecipients(recipients);
  if (!recipientListRaw.length) {
    return res.status(400).json({ message: "At least one recipient is required" });
  }
  const { valid: recipientList, invalid: invalidRecipients } = splitRecipientList(recipientListRaw);
  if (!recipientList.length) {
    return res
      .status(400)
      .json({
        message: invalidRecipients.length
          ? `All recipients are invalid. Please fix: ${invalidRecipients.slice(0, 5).join(", ")}`
          : "At least one valid recipient is required",
      });
  }
  if (invalidRecipients.length) {
    return res
      .status(400)
      .json({ message: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}` });
  }
  const owner = req.user.role === "admin" && req.body.owner ? req.body.owner : req.user.username;
  const users = (await readJson(authFilePath, { users: [] })).users || [];
  if (!users.some((u) => u.username === owner)) {
    return res.status(400).json({ message: `Unknown owner ${owner}` });
  }
  const now = new Date().toISOString();
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const storedAttachments = normalizeAttachmentPayloadForStorage(attachments);
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
    attachments: storedAttachments,
    status: "pending",
    transportHint: MAIL_TRANSPORT,
    createdAt: now,
    updatedAt: now,
  };
  payload.jobs.push(job);
  await writeJson(jobsFilePath, payload);
  await saveRecipients(job.id, recipientList);
  res.status(201).json(job);
});

app.get("/api/jobs/:id/recipients", requireAuth, async (req, res) => {
  const { id } = req.params;
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot access this job" });
  }
  const recipients = await loadRecipients(job);
  res.json({ recipients });
});

app.put("/api/jobs/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const {
    subject = "",
    fromName = "",
    replyTo = "",
    textBody = "",
    htmlBody = "",
    recipients,
    attachments,
    batchSize,
    delayBetweenBatches = 2,
    maxRetries = 3,
  } = req.body || {};
  if (!subject || !fromName) {
    return res.status(400).json({ message: "fromName and subject are required" });
  }
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot edit this job" });
  }
  const recipientListRaw = normalizeRecipients(recipients);
  if (!recipientListRaw.length) {
    return res.status(400).json({ message: "At least one recipient is required" });
  }
  const { valid: recipientList, invalid: invalidRecipients } = splitRecipientList(recipientListRaw);
  if (!recipientList.length) {
    return res
      .status(400)
      .json({
        message: invalidRecipients.length
          ? `All recipients are invalid. Please fix: ${invalidRecipients.slice(0, 5).join(", ")}`
          : "At least one valid recipient is required",
      });
  }
  if (invalidRecipients.length) {
    return res
      .status(400)
      .json({ message: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}` });
  }
  job.subject = subject;
  job.fromName = fromName;
  job.replyTo = replyTo || undefined;
  job.textBody = textBody;
  job.htmlBody = htmlBody;
  job.batchSize = parseInt(batchSize || job.batchSize || BATCH_SIZE_DEFAULT, 10);
  job.delayBetweenBatches = parseInt(delayBetweenBatches || job.delayBetweenBatches || 2, 10);
  job.maxRetries = parseInt(maxRetries || job.maxRetries || 3, 10);
  job.recipientsCount = recipientList.length;
  job.recipientsPreview = recipientList.slice(0, 5);
  if (!job.transportHint) {
    job.transportHint = MAIL_TRANSPORT;
  }
  if (attachments !== undefined) {
    job.attachments = normalizeAttachmentPayloadForStorage(attachments);
  } else if (!Array.isArray(job.attachments)) {
    job.attachments = [];
  }
  job.updatedAt = new Date().toISOString();
  job.status = "pending";
  delete job.lastResult;
  delete job.lastSentAt;
  job.sentCount = 0;
  job.failedCount = 0;
  delete job.error;
  await writeJson(jobsFilePath, payload);
  await saveRecipients(job.id, recipientList);
  res.json(job);
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

app.get("/api/activity", requireAuth, async (req, res) => {
  const { limit = 50, owner } = req.query || {};
  const data = await readActivityLog();
  let entries = data.entries || [];
  if (req.user.role !== "admin") {
    entries = entries.filter((entry) => entry.owner === req.user.username);
  } else if (owner) {
    entries = entries.filter((entry) => entry.owner === owner);
  }
  const size = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  res.json(entries.slice(0, size));
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

app.post("/api/jobs/:id/replay", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { skipRateLimit = false } = req.body || {};
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot replay this job" });
  }
  try {
    const replayResult = await replayExistingJob(job, payload, { skipRateLimit: Boolean(skipRateLimit) });
    res.json({
      message: "Job replay complete",
      job,
      result: replayResult,
    });
  } catch (err) {
    const status = err.statusCode || 500;
    res.status(status).json({ message: err.message || "Failed to replay job" });
  }
});

app.post("/admin/jobs/replay", requireAuth, requireAdmin, async (req, res) => {
  const {
    transport = "zoho",
    statuses,
    limit,
    dryRun = false,
    sort = "asc",
    includeUnknown,
  } = req.body || {};
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const normalizedStatuses = (Array.isArray(statuses) && statuses.length ? statuses : ["sent"]).map((s) =>
    String(s || "").toLowerCase()
  );
  let candidates = payload.jobs.filter((job) =>
    normalizedStatuses.includes(String(job.status || "").toLowerCase())
  );
  const includeUnknownTransports =
    includeUnknown !== undefined ? Boolean(includeUnknown) : transport === "zoho";
  if (transport) {
    candidates = candidates.filter((job) => {
      const storedTransport = storedJobTransport(job);
      if (storedTransport) return storedTransport === transport;
      return includeUnknownTransports;
    });
  }
  const sortFactor = sort === "desc" ? -1 : 1;
  candidates.sort((a, b) => {
    const timeA = new Date(a.updatedAt || a.lastSentAt || a.createdAt || 0).getTime();
    const timeB = new Date(b.updatedAt || b.lastSentAt || b.createdAt || 0).getTime();
    return (timeA - timeB) * sortFactor;
  });
  const selectionLimit = Number(limit) > 0 ? Number(limit) : 0;
  const selected = selectionLimit ? candidates.slice(0, selectionLimit) : candidates;
  if (!selected.length) {
    return res.json({ message: "No jobs matched filter", matched: candidates.length, processed: 0, results: [] });
  }
  if (dryRun) {
    return res.json({
      message: `Dry run: ${selected.length} job(s) would be replayed`,
      matched: candidates.length,
      processed: 0,
      results: selected.map((job) => ({
        id: job.id,
        subject: job.subject,
        status: job.status,
        transport: storedJobTransport(job) || determineJobTransport(job),
        recipientsCount: job.recipientsCount || 0,
      })),
    });
  }
  const results = [];
  for (const job of selected) {
    try {
      const replayResult = await replayExistingJob(job, payload, { skipRateLimit: true });
      results.push({
        id: job.id,
        subject: job.subject,
        sent: replayResult.sent,
        failed: replayResult.failed,
        transport: job.lastTransport || storedJobTransport(job) || determineJobTransport(job),
        status: job.status,
      });
    } catch (err) {
      results.push({
        id: job.id,
        subject: job.subject,
        transport: storedJobTransport(job) || determineJobTransport(job),
        error: err.message,
      });
    }
  }
  res.json({
    message: "Replay completed",
    matched: candidates.length,
    processed: selected.length,
    results,
  });
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

app.get("/admin/providers", requireAuth, requireAdmin, async (_req, res) => {
  const pool = await loadMailProviderPool();
  res.json(pool.providers);
});

app.post("/admin/providers", requireAuth, requireAdmin, async (req, res) => {
  try {
    const payload = sanitizeProviderPayload(req.body || {});
    const error = validateProviderConfig(payload.type, payload.config);
    if (error) {
      return res.status(400).json({ message: error });
    }
    const pool = await loadMailProviderPool();
    payload.id = uuid();
    payload.createdAt = new Date().toISOString();
    pool.providers.push(payload);
    await saveMailProviderPool(pool);
    res.status(201).json(payload);
  } catch (err) {
    res.status(500).json({ message: err.message || "Failed to create provider" });
  }
});

app.put("/admin/providers/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const pool = await loadMailProviderPool();
    const idx = pool.providers.findIndex((p) => p.id === id);
    if (idx === -1) return res.status(404).json({ message: "Provider not found" });
    const updated = sanitizeProviderPayload(req.body || {}, pool.providers[idx]);
    const error = validateProviderConfig(updated.type, updated.config);
    if (error) {
      return res.status(400).json({ message: error });
    }
    updated.id = id;
    updated.createdAt = pool.providers[idx].createdAt || updated.createdAt;
    pool.providers[idx] = updated;
    await saveMailProviderPool(pool);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: err.message || "Failed to update provider" });
  }
});

app.delete("/admin/providers/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const pool = await loadMailProviderPool();
    const idx = pool.providers.findIndex((p) => p.id === id);
    if (idx === -1) return res.status(404).json({ message: "Provider not found" });
    const removed = pool.providers.splice(idx, 1)[0];
    await saveMailProviderPool(pool);
    res.json({ message: "Provider removed", provider: removed });
  } catch (err) {
    res.status(500).json({ message: err.message || "Failed to remove provider" });
  }
});

app.post("/admin/providers/:id/reset-usage", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const pool = await loadMailProviderPool();
    const provider = pool.providers.find((p) => p.id === id);
    if (!provider) return res.status(404).json({ message: "Provider not found" });
    provider.usage = normalizeProviderUsage();
    await saveMailProviderPool(pool);
    res.json({ message: "Usage reset", provider });
  } catch (err) {
    res.status(500).json({ message: err.message || "Failed to reset usage" });
  }
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
  const recipientsRaw = await loadRecipients(job);
  if (!recipientsRaw.length) {
    throw new Error("This job does not have any recipients to send to.");
  }
  const { valid: recipients, invalid: invalidRecipients } = splitRecipientList(recipientsRaw);
  if (!recipients.length) {
    const invalidMsg = invalidRecipients.length
      ? `All recipients are invalid. Please fix: ${invalidRecipients.slice(0, 5).join(", ")}`
      : "This job does not have any valid recipients.";
    throw new Error(invalidMsg);
  }
  const batchSize = job.batchSize || BATCH_SIZE_DEFAULT;
  const results = [];
  let sentTotal = 0;
  let failedTotal = 0;
  const providersAvailable = await hasEnabledMailProviders();
  if (invalidRecipients.length) {
    const invalidDetails = invalidRecipients.map((recipient) => ({
      recipient,
      message: "Invalid email address",
      code: "INVALID_RECIPIENT",
    }));
    results.push({
      success: false,
      sent: 0,
      failed: invalidRecipients.length,
      recipients: invalidRecipients,
      transport: "validation",
      error: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}`,
      errorDetails: invalidDetails,
    });
    failedTotal += invalidRecipients.length;
  }

  for (let i = 0; i < recipients.length; i += batchSize) {
    const batch = recipients.slice(i, i + batchSize);
    try {
      if (providersAvailable) {
        const providerResult = await sendBatchUsingProviders(job, batch);
        if (providerResult) {
          results.push(providerResult);
          sentTotal += providerResult.sent;
          failedTotal += providerResult.failed;
          continue;
        }
      }
      const proxy = await getNextProxy();
      const useSes = MAIL_TRANSPORT === "ses" && !(await hasConfiguredSmtpPool());
      let smtpServer;
      if (MAIL_TRANSPORT === "zoho") {
        const zohoResult = await sendBatchWithZoho(job, batch);
        results.push(zohoResult);
        sentTotal += zohoResult.sent;
        failedTotal += zohoResult.failed;
      } else if (useSes) {
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

async function sendBatchWithSes(job, batch, proxyUrl, sesOptions = {}) {
  const region = sesOptions.region || AWS_REGION || "us-east-1";
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;
  const credentials =
    sesOptions.accessKeyId && sesOptions.secretAccessKey
      ? {
          accessKeyId: sesOptions.accessKeyId,
          secretAccessKey: sesOptions.secretAccessKey,
        }
      : undefined;
  const ses = new SESClient({
    region,
    credentials,
    requestHandler: new NodeHttpHandler(agent ? { httpsAgent: agent } : {}),
  });
  const sourceEmail = sesOptions.fromAddress || SES_FROM_ADDRESS || DEFAULT_FROM_ADDRESS || job.from;
  if (!sourceEmail) {
    throw new Error("No FROM email configured. Set SES_FROM or DEFAULT_FROM.");
  }
  const source = formatFromAddress(job.fromName || job.from, sourceEmail);
  const attachments = normalizeJobAttachments(job).map((att) => ({
    filename: att.filename,
    content: att.buffer,
    contentType: att.contentType,
  }));
  const transporter = nodemailer.createTransport({
    SES: { ses, aws: { SendRawEmailCommand } },
  });
  let sent = 0;
  let failed = 0;
  const errors = [];
  const errorDetails = [];
  for (const recipient of batch) {
    try {
      await transporter.sendMail({
        from: source,
        to: recipient,
        envelope: {
          from: sourceEmail,
          to: recipient,
        },
        subject: job.subject,
        text: job.textBody || (job.htmlBody ? stripHtml(job.htmlBody) : ""),
        html: job.htmlBody,
        replyTo: job.replyTo,
        attachments,
      });
      sent += 1;
    } catch (err) {
      failed += 1;
      errors.push(err.message);
      errorDetails.push({
        recipient,
        message: err.message,
        code: err?.responseCode || err.code,
        response: err?.response || err.message,
      });
      console.error(`SES send failure (${recipient}):`, err.message);
    }
  }
  return { success: failed === 0, sent, failed, recipients: batch, error: errors[0], errorDetails };
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
      await recordActivity(job, null, errMsg, null);
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
    const transportMeta = summarizeTransportDetails(result);
    if (transportMeta.lastTransport) {
      job.lastTransport = transportMeta.lastTransport;
    } else if (!job.lastTransport) {
      job.lastTransport = determineJobTransport(job);
    }
    if (transportMeta.lastProvider) {
      job.lastProviderSnapshot = transportMeta.lastProvider;
    }
    if (transportMeta.transports?.length) {
      job.transportHistory = mergeTransportHistory(job.transportHistory, transportMeta.transports);
    }
    const failureMsg = extractResultError(result);
    if (!result.success && failureMsg) {
      job.error = failureMsg;
    } else {
      delete job.error;
    }
    job.updatedAt = new Date().toISOString();
    await writeJson(jobsFilePath, payload);
    await recordActivity(job, result, null, transportMeta);
    return result;
  } catch (err) {
    job.status = "failed";
    job.error = err.message;
    job.updatedAt = new Date().toISOString();
    await writeJson(jobsFilePath, payload);
    await recordActivity(job, null, err.message, null);
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
        host: job.smtpHost || DEFAULT_SMTP_HOST,
        port: parseInt(job.smtpPort, 10) || DEFAULT_SMTP_PORT,
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
    connectionTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    greetingTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    socketTimeout: SMTP_SOCKET_TIMEOUT_MS,
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
  const errors = [];
  const errorDetails = [];
  const attachments = normalizeJobAttachments(job).map((att) => ({
    filename: att.filename,
    content: att.buffer,
    contentType: att.contentType,
  }));
  for (const recipient of batch) {
    try {
      await transporter.sendMail({
        from: fromAddress,
        replyTo: replyToAddress,
        to: recipient,
        subject: job.subject,
        text: job.textBody || (job.htmlBody ? stripHtml(job.htmlBody) : ""),
        html: job.htmlBody,
        attachments,
      });
      sent += 1;
    } catch (err) {
      failed += 1;
      errors.push(err.message);
      errorDetails.push({
        recipient,
        message: err.message,
        code: err && (err.responseCode || err.code),
        command: err && err.command,
        response: err && err.response,
      });
      console.error(
        `SMTP send failure (${smtpServer.label || smtpServer.username} -> ${recipient}):`,
        err.responseCode || err.code,
        err.response || err.message
      );
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
    error: errors[0],
    errorDetails,
  };
}

// ---------- Static ----------
app.use(express.static(staticDir));

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT} (serving static from ${staticDir})`);
});
