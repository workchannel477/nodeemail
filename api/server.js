import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs-extra";
import { fileURLToPath } from "url";
import { v4 as uuid } from "uuid";
import { Resend } from "resend";
import nodemailer from "nodemailer";
import { SocksProxyAgent } from "socks-proxy-agent";
import { createHash } from "crypto";
import { execSync } from "child_process";
import dotenv from "dotenv";
<<<<<<< HEAD
=======
import admin from "firebase-admin";
import fileUpload from "express-fileupload";
>>>>>>> f8d4db3c (New updates.)

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, "..");

dotenv.config({ path: path.join(rootDir, ".env") });

const ENV_ALIASES = {
  PORT: ["APP_PORT", "PORT"],
  SECRET_KEY: ["APP_SIGMA", "SECRET_KEY"],
  SESSION_TIMEOUT: ["APP_TAU", "SESSION_TIMEOUT"],
  MAX_REQUESTS_PER_MINUTE: ["APP_REQ_RATE", "MAX_REQUESTS_PER_MINUTE"],
  MAX_EMAILS_PER_MINUTE: ["APP_MAIL_CAP", "MAX_EMAILS_PER_MINUTE"],
  EMAIL_BATCH_SIZE: ["APP_BATCH", "EMAIL_BATCH_SIZE"],
  SMTP_CONNECTION_TIMEOUT_MS: ["APP_SMTP_CONN", "SMTP_CONNECTION_TIMEOUT_MS"],
  SMTP_SOCKET_TIMEOUT_MS: ["APP_SMTP_SOCKET", "SMTP_SOCKET_TIMEOUT_MS"],
<<<<<<< HEAD
  MAIL_TRANSPORT: ["APP_MAIL_TRANSPORT", "MAIL_TRANSPORT"],
  DEFAULT_FROM: ["APP_DEFAULT_FROM", "DEFAULT_FROM"],
  DEFAULT_SMTP_HOST: ["APP_SMTP_HOST", "DEFAULT_SMTP_HOST"],
  DEFAULT_SMTP_PORT: ["APP_SMTP_PORT", "DEFAULT_SMTP_PORT"],
  DATA_OBFUSCATION_KEY: ["APP_DATA_MASK", "DATA_OBFUSCATION_KEY"],
=======
  DEFAULT_SMTP_HOST: ["APP_SMTP_HOST", "DEFAULT_SMTP_HOST"],
  DEFAULT_SMTP_PORT: ["APP_SMTP_PORT", "DEFAULT_SMTP_PORT"],
  DEFAULT_FROM: ["APP_DEFAULT_FROM", "DEFAULT_FROM"],
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
      const value = secret ? decodeSecretValue(raw) : raw;
      return value;
=======
      return secret ? decodeSecretValue(raw) : raw;
>>>>>>> f8d4db3c (New updates.)
    }
  }
  return fallback;
}

<<<<<<< HEAD
const dataDir = path.join(rootDir, "data");
const logDir = path.join(rootDir, "logs");
const staticDir = path.join(rootDir, "public");
const recipientsDir = path.join(dataDir, "job-recipients");

=======
const staticDir = path.join(rootDir, "public");
const app = express();
const PORT = parseInt(envValue("PORT", "5001"), 10);
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_MINUTE = parseInt(envValue("MAX_REQUESTS_PER_MINUTE", "60"), 10);
const EMAIL_RATE_LIMIT = parseInt(envValue("MAX_EMAILS_PER_MINUTE", "30"), 10);
const BATCH_SIZE_DEFAULT = parseInt(envValue("EMAIL_BATCH_SIZE", "50"), 10);
const SMTP_ROTATE_AFTER_DEFAULT = 200;
const SMTP_CONNECTION_TIMEOUT_MS = parseInt(envValue("SMTP_CONNECTION_TIMEOUT_MS", "15000"), 10);
const SMTP_SOCKET_TIMEOUT_MS = parseInt(envValue("SMTP_SOCKET_TIMEOUT_MS", "20000"), 10);
const DATA_SYNC_DEFAULT_MESSAGE = "chore: sync data folder";
const DEFAULT_FROM_ADDRESS = envValue("DEFAULT_FROM", undefined, { secret: true });
const DEFAULT_SMTP_HOST = envValue("DEFAULT_SMTP_HOST", "smtp.example.com");
const DEFAULT_SMTP_PORT = parseInt(envValue("DEFAULT_SMTP_PORT", "587"), 10);
const SESSION_TIMEOUT_SECONDS = parseInt(envValue("SESSION_TIMEOUT", "3600"), 10);
// (removed file.io; using tmpfiles.org for uploads)
const DEFAULT_CREDITS = parseInt(envValue("DEFAULT_CREDITS", "100"), 10);
const DEFAULT_COST_PER_EMAIL = parseInt(envValue("DEFAULT_COST_PER_EMAIL", "1"), 10);

const sessions = new Map();
const apiRate = new Map();

// ---------- Firebase ----------
const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
  : null;

let db = null;
if (firebaseProjectId && firebaseClientEmail && firebasePrivateKey) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: firebaseProjectId,
        clientEmail: firebaseClientEmail,
        privateKey: firebasePrivateKey,
      }),
    });
    db = admin.firestore();
    db.settings({ ignoreUndefinedProperties: true });
    console.log("Firebase Firestore initialized.");
  } catch (err) {
    console.warn("Firebase initialization failed (falling back to file storage):", err.message);
  }
} else {
  console.warn("Firebase credentials not fully configured. Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY in .env. Falling back to file storage.");
}

// Keep file-based fallback
const dataDir = path.join(rootDir, "data");
const logDir = path.join(rootDir, "logs");
>>>>>>> f8d4db3c (New updates.)
const authFilePath = path.join(dataDir, "auth.json");
const jobsFilePath = path.join(dataDir, "email-jobs.json");
const ipRotationFilePath = path.join(dataDir, "ip-rotation.json");
const rateLimitFilePath = path.join(dataDir, "rate-limit.json");
const smtpPoolFilePath = path.join(dataDir, "smtp-pool.json");
const mailProvidersFilePath = path.join(dataDir, "mail-providers.json");
const activityLogPath = path.join(dataDir, "activity-log.json");
<<<<<<< HEAD
<<<<<<< HEAD

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
const MAIL_TRANSPORT = (envValue("MAIL_TRANSPORT", "resend") || "resend").toLowerCase();
const DEFAULT_FROM_ADDRESS = envValue("DEFAULT_FROM", undefined, { secret: true });
const DEFAULT_SMTP_HOST = envValue("DEFAULT_SMTP_HOST", "smtp.example.com");
const DEFAULT_SMTP_PORT = parseInt(envValue("DEFAULT_SMTP_PORT", "587"), 10);
const DATA_OBFUSCATION_KEY = envValue("DATA_OBFUSCATION_KEY", "nodeemail", { secret: true }) || "nodeemail";
const SESSION_TIMEOUT_SECONDS = parseInt(envValue("SESSION_TIMEOUT", "3600"), 10);

const sessions = new Map();
const apiRate = new Map();
=======
=======
const appSettingsPath = path.join(dataDir, "app-settings.json");
>>>>>>> 102efad6 (feat: implement app settings management, migrate file uploads to tmpfiles.org, and add Firebase sync utilities)
const recipientsDir = path.join(dataDir, "job-recipients");
>>>>>>> f8d4db3c (New updates.)

ensureDataFiles();

app.use(cors());
<<<<<<< HEAD
app.use(express.json({ limit: "2mb" }));
=======
app.use(express.json({ limit: "10mb" }));
app.use(fileUpload({ limits: { fileSize: 50 * 1024 * 1024 }, useTempFiles: false }));
>>>>>>> f8d4db3c (New updates.)

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

<<<<<<< HEAD
// ---------- Helpers ----------
=======
// ---------- Firebase/Firestore Helpers ----------
function fbCollection(name) {
  return db ? db.collection(name) : null;
}

async function fbGet(collectionName, docId) {
  const col = fbCollection(collectionName);
  if (!col) return null;
  const snap = await col.doc(docId).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

async function fbSet(collectionName, docId, data) {
  const col = fbCollection(collectionName);
  if (!col) return;
  await col.doc(docId).set(data, { merge: true });
}

async function fbDelete(collectionName, docId) {
  const col = fbCollection(collectionName);
  if (!col) return;
  await col.doc(docId).delete();
}

async function fbQuery(collectionName, field, op, value) {
  const col = fbCollection(collectionName);
  if (!col) return [];
  const snap = await col.where(field, op, value).get();
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

async function fbAll(collectionName) {
  const col = fbCollection(collectionName);
  if (!col) return [];
  const snap = await col.get();
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

// ---------- File-based fallback helpers ----------
>>>>>>> f8d4db3c (New updates.)
async function ensureDataFiles() {
  await fs.ensureDir(dataDir);
  await fs.ensureDir(logDir);
  await fs.ensureDir(recipientsDir);
<<<<<<< HEAD
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
=======

  if (!(await fs.pathExists(authFilePath))) {
    const salt = cryptoSalt();
    const user = {
      id: "admin",
      username: "admin",
      role: "admin",
      status: "active",
      salt,
      passwordHash: hashPassword("admin123", salt),
      mailboxes: [],
      credits: DEFAULT_CREDITS,
      creditsUsed: 0,
      costPerEmail: DEFAULT_COST_PER_EMAIL,
      features: { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    if (db) {
      await db.collection("users").doc(user.id).set(user);
    } else {
      await writeJsonFallback(authFilePath, { users: [user] });
    }
  }
  if (!(await fs.pathExists(jobsFilePath))) {
    await writeJsonFallback(jobsFilePath, { jobs: [] });
  }
  if (!(await fs.pathExists(ipRotationFilePath))) {
    await writeJsonFallback(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  }
  if (!(await fs.pathExists(rateLimitFilePath))) {
    await writeJsonFallback(rateLimitFilePath, { limits: {} });
  }
  if (!(await fs.pathExists(smtpPoolFilePath))) {
    await writeJsonFallback(smtpPoolFilePath, { servers: [], currentIndex: 0, sentSinceRotation: 0, rotateAfter: SMTP_ROTATE_AFTER_DEFAULT });
  }
  if (!(await fs.pathExists(activityLogPath))) {
    await writeJsonFallback(activityLogPath, { entries: [] });
  }
  if (!(await fs.pathExists(mailProvidersFilePath))) {
    await writeJsonFallback(mailProvidersFilePath, { providers: [], rotationIndex: 0 });
  }
  if (!(await fs.pathExists(appSettingsPath))) {
    await writeJsonFallback(appSettingsPath, { paymentDetails: '', telegramLink: '' });
  }
}

const DATA_KEY_BUFFER = Buffer.from(envValue("DATA_OBFUSCATION_KEY", "nodeemail") || "nodeemail");
>>>>>>> f8d4db3c (New updates.)

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
<<<<<<< HEAD
  return {
    __obf: true,
    __v: 1,
    __data: obfuscatePayload(value),
  };
=======
  return { __obf: true, __v: 1, __data: obfuscatePayload(value) };
>>>>>>> f8d4db3c (New updates.)
}

function unwrapObfuscated(parsed) {
  if (parsed && parsed.__obf && parsed.__data) {
<<<<<<< HEAD
    try {
      return revealPayload(parsed.__data);
    } catch (err) {
      return parsed;
    }
=======
    try { return revealPayload(parsed.__data); } catch (err) { return parsed; }
>>>>>>> f8d4db3c (New updates.)
  }
  return parsed;
}

<<<<<<< HEAD
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
=======
async function readJsonFallback(filePath, fallback = {}) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    if (!raw.trim()) return fallback;
    return unwrapObfuscated(JSON.parse(raw));
  } catch (err) {
    if (err.code === "ENOENT") {
      await writeJsonFallback(filePath, fallback);
>>>>>>> f8d4db3c (New updates.)
      return fallback;
    }
    throw err;
  }
}

<<<<<<< HEAD
async function writeJson(filePath, value) {
  const wrapped = wrapObfuscated(value);
  await fs.outputFile(filePath, JSON.stringify(wrapped));
}

=======
async function writeJsonFallback(filePath, value) {
  await fs.outputFile(filePath, JSON.stringify(wrapObfuscated(value)));
}

// ---------- Auth Helpers ----------
>>>>>>> f8d4db3c (New updates.)
function hashPassword(password, salt) {
  return createHash("sha256").update(`${salt}${password}`).digest("hex");
}

function cryptoSalt() {
  return uuid().replace(/-/g, "");
}

function normalizeUserRole(role = "user") {
  return String(role || "user").toLowerCase() === "admin" ? "admin" : "user";
}

function normalizeUserStatus(status = "active") {
  return String(status || "active").toLowerCase() === "suspended" ? "suspended" : "active";
}

function sanitizeUserForResponse(user = {}) {
  return {
    id: user.id,
    username: user.username,
    role: normalizeUserRole(user.role),
    status: normalizeUserStatus(user.status),
    mailboxes: Array.isArray(user.mailboxes) ? user.mailboxes : [],
<<<<<<< HEAD
=======
    credits: user.credits || 0,
    creditsUsed: user.creditsUsed || 0,
    costPerEmail: user.costPerEmail || DEFAULT_COST_PER_EMAIL,
    features: user.features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 },
>>>>>>> f8d4db3c (New updates.)
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

<<<<<<< HEAD
async function loadAuthStore() {
  const payload = await readJson(authFilePath, { users: [] });
  if (!Array.isArray(payload.users)) {
    if (payload && payload.__obf && payload.__data) {
      throw new Error("Unable to decode auth store. Verify DATA_OBFUSCATION_KEY / APP_DATA_MASK.");
    }
    payload.users = [];
  }
  return payload;
}

async function saveAuthStore(payload) {
  payload.users = Array.isArray(payload.users) ? payload.users : [];
  await writeJson(authFilePath, payload);
=======
// ---------- Users (Firebase-first) ----------
async function loadAuthStore() {
  if (db) {
    const usersSnap = await db.collection("users").get();
    const users = usersSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    if (users.length) return { users };
  }
  return readJsonFallback(authFilePath, { users: [] });
}

async function saveAuthStore(payload) {
  if (db) {
    const batch = db.batch();
    for (const user of payload.users || []) {
      const id = user.id || uuid();
      batch.set(db.collection("users").doc(id), user, { merge: true });
    }
    await batch.commit();
  } else {
    await writeJsonFallback(authFilePath, payload);
  }
}

async function findUserByUsername(username) {
  if (db) {
    const snap = await db.collection("users").where("username", "==", username).get();
    if (!snap.empty) {
      const doc = snap.docs[0];
      return { id: doc.id, ...doc.data() };
    }
  }
  const payload = await readJsonFallback(authFilePath, { users: [] });
  return (payload.users || []).find((u) => u.username === username) || null;
}

async function findUserById(id) {
  if (db) {
    const doc = await db.collection("users").doc(id).get();
    if (doc.exists) return { id: doc.id, ...doc.data() };
  }
  const payload = await readJsonFallback(authFilePath, { users: [] });
  return (payload.users || []).find((u) => u.id === id) || null;
}

async function updateUserInDb(id, updates) {
  if (db) {
    await db.collection("users").doc(id).update(updates);
  } else {
    const payload = await readJsonFallback(authFilePath, { users: [] });
    const idx = payload.users.findIndex((u) => u.id === id);
    if (idx !== -1) {
      payload.users[idx] = { ...payload.users[idx], ...updates };
      await writeJsonFallback(authFilePath, payload);
    }
  }
}

// ---------- Jobs ----------
async function loadJobsCollection() {
  if (db) {
    const snap = await db.collection("jobs").orderBy("updatedAt", "desc").get();
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  }
  const payload = await readJsonFallback(jobsFilePath, { jobs: [] });
  return payload.jobs || [];
}

async function saveJob(job) {
  if (db) {
    const id = job.id || uuid();
    job.id = id;
    await db.collection("jobs").doc(id).set(job, { merge: true });
    return job;
  }
  const payload = await readJsonFallback(jobsFilePath, { jobs: [] });
  const idx = payload.jobs.findIndex((j) => j.id === job.id);
  if (idx !== -1) {
    payload.jobs[idx] = job;
  } else {
    payload.jobs.push(job);
  }
  await writeJsonFallback(jobsFilePath, payload);
  return job;
}

async function findJobById(id) {
  if (db) {
    const doc = await db.collection("jobs").doc(id).get();
    return doc.exists ? { id: doc.id, ...doc.data() } : null;
  }
  const payload = await readJsonFallback(jobsFilePath, { jobs: [] });
  return payload.jobs.find((j) => j.id === id) || null;
}

async function deleteJobFromDb(id) {
  if (db) {
    await db.collection("jobs").doc(id).delete();
  } else {
    const payload = await readJsonFallback(jobsFilePath, { jobs: [] });
    payload.jobs = payload.jobs.filter((j) => j.id !== id);
    await writeJsonFallback(jobsFilePath, payload);
  }
}

async function saveRecipientsToDb(jobId, recipients = []) {
  if (db) {
    await db.collection("jobRecipients").doc(jobId).set({ recipients });
  } else {
    recipientsFile(jobId);
    await writeJsonFallback(path.join(recipientsDir, `${jobId}.json`), { recipients });
  }
}

async function loadRecipientsFromDb(jobId) {
  if (db) {
    const doc = await db.collection("jobRecipients").doc(jobId).get();
    return doc.exists ? (doc.data().recipients || []) : [];
  }
  try {
    const data = await readJsonFallback(path.join(recipientsDir, `${jobId}.json`), { recipients: [] });
    return Array.isArray(data.recipients) ? data.recipients : [];
  } catch (err) {
    return [];
  }
}

async function deleteRecipientsFromDb(jobId) {
  if (db) {
    await db.collection("jobRecipients").doc(jobId).delete();
  } else {
    await fs.remove(path.join(recipientsDir, `${jobId}.json`));
  }
>>>>>>> f8d4db3c (New updates.)
}

function recipientsFile(jobId) {
  return path.join(recipientsDir, `${jobId}.json`);
}

<<<<<<< HEAD
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

=======
// ---------- Activity ----------
async function readActivityLog() {
  if (db) {
    const snap = await db.collection("activity").orderBy("timestamp", "desc").limit(200).get();
    return { entries: snap.docs.map((d) => ({ id: d.id, ...d.data() })) };
  }
  return readJsonFallback(activityLogPath, { entries: [] });
}

async function appendActivityLog(entry) {
  entry.id = entry.id || uuid();
  entry.timestamp = entry.timestamp || new Date().toISOString();
  if (db) {
    await db.collection("activity").add(entry);
  } else {
    const payload = await readJsonFallback(activityLogPath, { entries: [] });
    payload.entries = payload.entries || [];
    payload.entries.unshift(entry);
    if (payload.entries.length > 200) payload.entries = payload.entries.slice(0, 200);
    await writeJsonFallback(activityLogPath, payload);
  }
}

// ---------- Mail Providers ----------
async function loadMailProviderPool() {
  if (db) {
    const doc = await db.collection("config").doc("mailProviders").get();
    if (doc.exists) return doc.data();
    return { providers: [], rotationIndex: 0 };
  }
  return readJsonFallback(mailProvidersFilePath, { providers: [], rotationIndex: 0 });
}

async function saveMailProviderPool(pool) {
  if (db) {
    await db.collection("config").doc("mailProviders").set(pool);
  } else {
    await writeJsonFallback(mailProvidersFilePath, pool);
  }
}

// ---------- SMTP Pool ----------
async function loadSmtpPool() {
  if (db) {
    const doc = await db.collection("config").doc("smtpPool").get();
    if (doc.exists) return doc.data();
    return { servers: [], currentIndex: 0, sentSinceRotation: 0, rotateAfter: SMTP_ROTATE_AFTER_DEFAULT };
  }
  return readJsonFallback(smtpPoolFilePath, { servers: [], currentIndex: 0, sentSinceRotation: 0, rotateAfter: SMTP_ROTATE_AFTER_DEFAULT });
}

async function saveSmtpPool(payload) {
  if (db) {
    await db.collection("config").doc("smtpPool").set(payload);
  } else {
    await writeJsonFallback(smtpPoolFilePath, payload);
  }
}

// ---------- IP Rotation ----------
async function readIpRotation() {
  if (db) {
    const doc = await db.collection("config").doc("ipRotation").get();
    return doc.exists ? doc.data() : { proxies: [], currentIndex: 0 };
  }
  return readJsonFallback(ipRotationFilePath, { proxies: [], currentIndex: 0 });
}

async function writeIpRotation(data) {
  if (db) {
    await db.collection("config").doc("ipRotation").set(data);
  } else {
    await writeJsonFallback(ipRotationFilePath, data);
  }
}

// ---------- Rate Limits ----------
async function readRateLimits() {
  if (db) {
    const doc = await db.collection("config").doc("rateLimits").get();
    return doc.exists ? doc.data() : { limits: {} };
  }
  return readJsonFallback(rateLimitFilePath, { limits: {} });
}

async function writeRateLimits(data) {
  if (db) {
    await db.collection("config").doc("rateLimits").set(data);
  } else {
    await writeJsonFallback(rateLimitFilePath, data);
  }
}

// ---------- App Settings ----------
async function readAppSettings() {
  if (db) {
    const doc = await db.collection("config").doc("appSettings").get();
    return doc.exists ? doc.data() : { paymentDetails: '', telegramLink: '' };
  }
  return readJsonFallback(appSettingsPath, { paymentDetails: '', telegramLink: '' });
}

async function saveAppSettings(data) {
  if (db) {
    await db.collection("config").doc("appSettings").set(data);
  } else {
    await writeJsonFallback(appSettingsPath, data);
  }
}

// ---------- Credits ----------
async function deductCredits(username, amount) {
  if (!amount || amount <= 0) return true;
  if (db) {
    const snap = await db.collection("users").where("username", "==", username).get();
    if (!snap.empty) {
      const doc = snap.docs[0];
      const user = doc.data();
      const currentCredits = user.credits || 0;
      if (currentCredits < amount) return false;
      await doc.ref.update({
        credits: admin.firestore.FieldValue.increment(-amount),
        creditsUsed: (user.creditsUsed || 0) + amount,
        updatedAt: new Date().toISOString(),
      });
      return true;
    }
  }
  const payload = await readJsonFallback(authFilePath, { users: [] });
  const user = payload.users.find((u) => u.username === username);
  if (!user) return false;
  const currentCredits = user.credits || 0;
  if (currentCredits < amount) return false;
  user.credits = currentCredits - amount;
  user.creditsUsed = (user.creditsUsed || 0) + amount;
  user.updatedAt = new Date().toISOString();
  await writeJsonFallback(authFilePath, payload);
  return true;
}

async function getUserCredits(username) {
  if (db) {
    const snap = await db.collection("users").where("username", "==", username).get();
    if (!snap.empty) {
      const user = snap.docs[0].data();
      return {
        credits: user.credits || 0,
        creditsUsed: user.creditsUsed || 0,
        costPerEmail: user.costPerEmail || DEFAULT_COST_PER_EMAIL,
      };
    }
  }
  const payload = await readJsonFallback(authFilePath, { users: [] });
  const user = payload.users.find((u) => u.username === username);
  if (!user) return { credits: 0, creditsUsed: 0, costPerEmail: DEFAULT_COST_PER_EMAIL };
  return {
    credits: user.credits || 0,
    creditsUsed: user.creditsUsed || 0,
    costPerEmail: user.costPerEmail || DEFAULT_COST_PER_EMAIL,
  };
}

async function getUserFeatures(username) {
  if (db) {
    const snap = await db.collection("users").where("username", "==", username).get();
    if (!snap.empty) {
      return snap.docs[0].data().features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 };
    }
  }
  const payload = await readJsonFallback(authFilePath, { users: [] });
  const user = payload.users.find((u) => u.username === username);
  if (!user) return { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 };
  return user.features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 };
}

// ---------- Helpers (existing functionality) ----------
>>>>>>> f8d4db3c (New updates.)
const RECIPIENT_DELIMITER_REGEX = /[\s,;|:]+/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

function flattenRecipientInput(value) {
  if (value == null) return [];
<<<<<<< HEAD
  if (Array.isArray(value)) {
    return value.flatMap(flattenRecipientInput);
  }
  if (typeof value === "string") {
    return value.split(RECIPIENT_DELIMITER_REGEX);
  }
=======
  if (Array.isArray(value)) return value.flatMap(flattenRecipientInput);
  if (typeof value === "string") return value.split(RECIPIENT_DELIMITER_REGEX);
>>>>>>> f8d4db3c (New updates.)
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
  const normalized = flattenRecipientInput(recipients)
    .map((r) => attemptRecipientRepair(String(r).trim().toLowerCase()))
    .filter(Boolean);
  return Array.from(new Set(normalized));
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

<<<<<<< HEAD
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
=======
async function loadRecipients(job) {
  const collected = [];
  const fromDb = await loadRecipientsFromDb(job.id);
  collected.push(...fromDb);
  if (Array.isArray(job.recipients)) collected.push(...job.recipients);
  if (typeof job.recipients === "string") collected.push(...normalizeRecipients(job.recipients));
  return normalizeRecipients(collected);
}

async function loadRecipientsPreview(jobId, limit = 5, fallbackList = []) {
  const fromDb = await loadRecipientsFromDb(jobId);
  const list = fromDb.length ? fromDb : (Array.isArray(fallbackList) ? fallbackList : normalizeRecipients(fallbackList));
  return { recipientsPreview: list.slice(0, limit), recipientsCount: list.length };
>>>>>>> f8d4db3c (New updates.)
}

function extractResultError(result = {}) {
  if (Array.isArray(result.results)) {
    for (const batch of result.results) {
      if (batch && Array.isArray(batch.errorDetails) && batch.errorDetails.length) {
        const detail = batch.errorDetails[0] || {};
<<<<<<< HEAD
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
=======
        if (detail.code) return `SMTP error ${detail.code}: ${detail.message || detail.response || "Unknown error"}`;
        if (detail.message || detail.response) return detail.message || detail.response;
      }
      if (batch && batch.error) return batch.error;
      if (batch && batch.failed > 0) return `Failed to send to ${batch.failed} recipient(s)`;
>>>>>>> f8d4db3c (New updates.)
    }
  }
  return null;
}

function summarizeSend(job, result) {
  const total = job.recipientsCount || (result ? (result.sent || 0) + (result.failed || 0) : 0);
  return `Sent ${result?.sent || 0}/${total || 0} emails`;
}

<<<<<<< HEAD
=======
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

>>>>>>> f8d4db3c (New updates.)
async function recordActivity(job, result, errorMessage, transportMeta) {
  const summaryMessage = errorMessage || extractResultError(result) || summarizeSend(job, result);
  const flattenedDetails = Array.isArray(result?.results)
    ? result.results.flatMap((batch) => batch.errorDetails || []).slice(0, 20)
    : [];
  const transportDetails = transportMeta || summarizeTransportDetails(result);
<<<<<<< HEAD
  const entryTransport = job.lastTransport || transportDetails.lastTransport || determineJobTransport(job);
  const entry = {
    id: uuid(),
=======
  const entryTransport = job.lastTransport || (transportDetails ? transportDetails.lastTransport : null) || "resend";
  const entry = {
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (transportDetails?.transports?.length) {
    entry.transports = transportDetails.transports.slice(-20);
  }
  if (transportDetails?.lastProvider) {
    entry.provider = transportDetails.lastProvider;
  }
  await appendActivityLog(entry);
}

=======
  if (transportDetails?.transports?.length) entry.transports = transportDetails.transports.slice(-20);
  if (transportDetails?.lastProvider) entry.provider = transportDetails.lastProvider;
  await appendActivityLog(entry);
}

function determineJobTransport(job = {}) {
  return job.lastTransport || job.transportHint || "resend";
}

function storedJobTransport(job = {}) {
  return job.lastTransport || job.transportHint || null;
}

function mergeTransportHistory(existing = [], additions = []) {
  return [...(existing || []), ...(additions || [])].slice(-50);
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

function formatFromAddress(name, email) {
  if (!email) return name || "";
  if (name) return `${name} <${email}>`;
  return email;
}

function stripHtml(html) {
  return html.replace(/<[^>]+>/g, " ");
}

function buildSendSummary(result = {}) {
  return { sent: result.sent || 0, failed: result.failed || 0, batches: Array.isArray(result.results) ? result.results.length : 0 };
}

function extractToken(req) {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) return header.substring(7).trim();
  if (req.body && typeof req.body.token === "string") return req.body.token;
  return null;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token || !sessions.has(token)) return res.status(401).json({ message: "Missing or invalid session" });
  const session = sessions.get(token);
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ message: "Session expired" });
  }
  req.user = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ message: "Admin access required" });
  next();
}

// ---------- Mail Provider Functions (existing) ----------
>>>>>>> f8d4db3c (New updates.)
function normalizeProviderUsage(usage = {}) {
  return {
    dayKey: usage.dayKey || new Date().toISOString().slice(0, 10),
    sentToday: Number(usage.sentToday) || 0,
<<<<<<< HEAD
    minuteWindow: Array.isArray(usage.minuteWindow)
      ? usage.minuteWindow.map((ts) => Number(ts)).filter((ts) => Number.isFinite(ts))
      : [],
=======
    minuteWindow: Array.isArray(usage.minuteWindow) ? usage.minuteWindow.map((ts) => Number(ts)).filter((ts) => Number.isFinite(ts)) : [],
>>>>>>> f8d4db3c (New updates.)
  };
}

function normalizeMailProvider(provider = {}) {
  return {
    id: provider.id || uuid(),
    name: provider.name || "Provider",
    type: (provider.type || "resend").toLowerCase(),
    enabled: provider.enabled !== false,
    quotaPerMinute: Number(provider.quotaPerMinute) || 60,
    quotaPerDay: Number(provider.quotaPerDay) || 1000,
    config: provider.config || {},
    usage: normalizeProviderUsage(provider.usage),
    createdAt: provider.createdAt || new Date().toISOString(),
    updatedAt: provider.updatedAt || new Date().toISOString(),
  };
}

<<<<<<< HEAD
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

=======
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (provider.quotaPerDay > 0 && provider.usage.sentToday + batchSize > provider.quotaPerDay) {
    return false;
  }
  // Per-minute quota is treated as provider dispatch attempts per minute.
  // The daily quota remains recipient-count based.
  if (provider.quotaPerMinute > 0 && provider.usage.minuteWindow.length + 1 > provider.quotaPerMinute) {
    return false;
  }
=======
  if (provider.quotaPerDay > 0 && provider.usage.sentToday + batchSize > provider.quotaPerDay) return false;
  if (provider.quotaPerMinute > 0 && provider.usage.minuteWindow.length + 1 > provider.quotaPerMinute) return false;
>>>>>>> f8d4db3c (New updates.)
  return true;
}

function isSupportedProviderType(type) {
  const normalized = String(type || "").toLowerCase();
  return normalized === "resend" || normalized === "smtp";
}

async function incrementProviderUsage(providerId, increment) {
  if (!providerId || !increment) return;
  const pool = await loadMailProviderPool();
  const provider = pool.providers.find((p) => p.id === providerId);
  if (!provider) return;
  const now = Date.now();
  ensureProviderUsage(provider, now);
  provider.usage.minuteWindow.push(now);
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
<<<<<<< HEAD
    if (
      !provider ||
      !provider.enabled ||
      excludeIds.includes(provider.id) ||
      !isSupportedProviderType(provider.type)
    ) {
      continue;
    }
=======
    if (!provider || !provider.enabled || excludeIds.includes(provider.id) || !isSupportedProviderType(provider.type)) continue;
>>>>>>> f8d4db3c (New updates.)
    if (ensureProviderUsage(provider, now)) mutated = true;
    if (!providerCanSend(provider, batchSize, now)) continue;
    pool.rotationIndex = (idx + 1) % providers.length;
    mutated = true;
<<<<<<< HEAD
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
  const type = provider.type || "resend";
  const config = provider.config || {};
  if (type === "resend") {
    return sendBatchWithResend(job, batch, config);
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

=======
    if (mutated) await saveMailProviderPool(pool);
    return provider;
  }
  if (mutated) await saveMailProviderPool(pool);
  return null;
}

>>>>>>> f8d4db3c (New updates.)
async function hasEnabledMailProviders() {
  const pool = await loadMailProviderPool();
  return pool.providers.some((p) => p.enabled && isSupportedProviderType(p.type));
}

function validateProviderConfig(type, config = {}) {
  if (type === "resend") {
    const required = ["apiKey", "fromAddress"];
    const missing = required.filter((key) => !config[key]);
    if (missing.length) return `Resend provider missing: ${missing.join(", ")}`;
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
  if (payload.type !== undefined) provider.type = String(payload.type || "resend").toLowerCase();
  if (payload.enabled !== undefined) provider.enabled = Boolean(payload.enabled);
<<<<<<< HEAD
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
=======
  if (payload.quotaPerMinute !== undefined) provider.quotaPerMinute = Math.max(0, parseInt(payload.quotaPerMinute, 10) || 0);
  if (payload.quotaPerDay !== undefined) provider.quotaPerDay = Math.max(0, parseInt(payload.quotaPerDay, 10) || 0);
  if (payload.config !== undefined) provider.config = payload.config && typeof payload.config === "object" ? payload.config : provider.config || {};
>>>>>>> f8d4db3c (New updates.)
  provider.updatedAt = new Date().toISOString();
  return normalizeMailProvider(provider);
}

function normalizeJobAttachments(job) {
<<<<<<< HEAD
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

=======
  if (!Array.isArray(job?.attachments)) return [];
  return job.attachments.map((att) => {
    if (!att || !att.filename) return null;
    if (att.url) {
      return { filename: att.filename, contentType: att.contentType || "application/octet-stream", url: att.url, path: att.url };
    }
    if (att.content) {
      const encoding = att.encoding || "base64";
      try {
        return { filename: att.filename, contentType: att.contentType || "application/octet-stream", content: Buffer.from(att.content, encoding) };
      } catch (err) {
        return null;
      }
    }
    return null;
  }).filter(Boolean);
}

// ---------- SMTP Functions ----------
function sanitizeSmtp(server) {
  if (!server) return server;
  const { password, ...rest } = server;
  return rest;
}

function normalizeRotateAfter(value) {
  const parsed = parseInt(value || SMTP_ROTATE_AFTER_DEFAULT, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : SMTP_ROTATE_AFTER_DEFAULT;
}

async function pickSmtpServer() {
  const pool = await loadSmtpPool();
  if (!pool.servers.length) throw new Error("No SMTP servers configured. Ask an admin to add at least one SMTP account.");
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
  if (mutated) await saveSmtpPool(pool);
  return { ...pool.servers[pool.currentIndex], __fromPool: true };
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

async function hasConfiguredSmtpPool() {
  const pool = await loadSmtpPool();
  return (pool.servers || []).length > 0;
}

async function resolveSmtpServerForBatch(job) {
  try {
    return await pickSmtpServer();
  } catch (err) {
    if (job.smtpUsername && job.smtpPassword) {
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

async function getNextProxy() {
  const payload = await readIpRotation();
  const { proxies = [], currentIndex = 0 } = payload;
  if (!proxies.length) return null;
  const proxy = proxies[currentIndex % proxies.length];
  payload.currentIndex = (currentIndex + 1) % proxies.length;
  await writeIpRotation(payload);
  return proxy;
}

// ---------- Email Rate Limit ----------
async function checkEmailRateLimit(username) {
  const data = await readRateLimits();
  data.limits = data.limits || {};
  const now = Date.now();
  const entries = (data.limits[username] || []).filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
  if (entries.length >= EMAIL_RATE_LIMIT) return false;
  entries.push(now);
  data.limits[username] = entries;
  await writeRateLimits(data);
  return true;
}

// ---------- File Upload (tmpfiles.org with local fallback) ----------
const uploadsDir = path.join(staticDir, "uploads");

async function uploadToTmpFiles(fileBuffer, fileName) {
  const formData = new FormData();
  const blob = new Blob([fileBuffer]);
  formData.append("file", blob, fileName);
  const response = await fetch("https://tmpfiles.org/api/v1/upload", { method: "POST", body: formData });
  const data = await response.json();
  if (!data || !data.data || !data.data.url) throw new Error("tmpfiles.org: unexpected response");
  const dlUrl = data.data.url.replace("https://tmpfiles.org/", "https://tmpfiles.org/dl/");
  return { url: dlUrl, key: "", expiry: "30+ days" };
}

async function saveLocalFile(fileBuffer, fileName) {
  const safe = fileName.replace(/[^a-zA-Z0-9._-]/g, "_");
  const unique = `${Date.now()}-${Math.random().toString(36).slice(2)}-${safe}`;
  await fs.mkdirp(uploadsDir);
  await fs.writeFile(path.join(uploadsDir, unique), fileBuffer);
  return { url: `/uploads/${unique}`, key: "", expiry: "permanent" };
}

// ---------- Resend Rate Limiting ----------
>>>>>>> f8d4db3c (New updates.)
const RESEND_REQUESTS_PER_SECOND_DEFAULT = 2;
const RESEND_RATE_WINDOW_MS = 1_000;
const RESEND_RATE_RETRY_DELAY_MS = 600;
const RESEND_RATE_RETRY_MAX_ATTEMPTS = 2;
const resendRequestTimestamps = [];

function normalizeResendRequestsPerSecond(value) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : RESEND_REQUESTS_PER_SECOND_DEFAULT;
}

async function throttleResendRequest(maxRequestsPerSecond = RESEND_REQUESTS_PER_SECOND_DEFAULT) {
  const maxRequests = normalizeResendRequestsPerSecond(maxRequestsPerSecond);
  while (true) {
    const now = Date.now();
    while (resendRequestTimestamps.length && now - resendRequestTimestamps[0] >= RESEND_RATE_WINDOW_MS) {
      resendRequestTimestamps.shift();
    }
    if (resendRequestTimestamps.length < maxRequests) {
      resendRequestTimestamps.push(now);
      return;
    }
    const waitMs = Math.max(25, RESEND_RATE_WINDOW_MS - (now - resendRequestTimestamps[0]) + 10);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
}

function isResendRateLimitError(errLike) {
  const message = String(errLike?.message || errLike || "").toLowerCase();
<<<<<<< HEAD
  const code =
    String(errLike?.statusCode || errLike?.status || errLike?.code || errLike?.name || "").toLowerCase();
  return (
    message.includes("too many requests") ||
    message.includes("rate limit") ||
    code === "429" ||
    code.includes("rate")
  );
}

async function sendBatchWithResend(job, batch, config = {}) {
  const apiKey = config.apiKey || config.token;
  if (!apiKey) {
    return {
      success: false,
      sent: 0,
      failed: batch.length,
      recipients: batch,
      transport: "resend",
      error: "Resend API key is not configured",
      errorDetails: [{ message: "Resend API key is not configured" }],
    };
  }
  const fromAddress = config.fromAddress || job.from || DEFAULT_FROM_ADDRESS;
  if (!fromAddress) {
    return {
      success: false,
      sent: 0,
      failed: batch.length,
      recipients: batch,
      transport: "resend",
      error: "No from address configured for Resend provider",
      errorDetails: [{ message: "No from address configured for Resend provider" }],
    };
  }

=======
  const code = String(errLike?.statusCode || errLike?.status || errLike?.code || errLike?.name || "").toLowerCase();
  return message.includes("too many requests") || message.includes("rate limit") || code === "429" || code.includes("rate");
}

// ---------- Send Functions ----------
async function sendBatchWithResend(job, batch, config = {}) {
  const apiKey = config.apiKey || config.token;
  if (!apiKey) {
    return { success: false, sent: 0, failed: batch.length, recipients: batch, transport: "resend", error: "Resend API key is not configured", errorDetails: [{ message: "Resend API key is not configured" }] };
  }
  const fromAddress = config.fromAddress || job.from || DEFAULT_FROM_ADDRESS;
  if (!fromAddress) {
    return { success: false, sent: 0, failed: batch.length, recipients: batch, transport: "resend", error: "No from address configured for Resend provider", errorDetails: [{ message: "No from address configured for Resend provider" }] };
  }
>>>>>>> f8d4db3c (New updates.)
  const resend = new Resend(apiKey);
  const fromName = config.fromName || job.fromName || job.from || "Mailer";
  const from = formatFromAddress(fromName, fromAddress);
  const originalHtml = job.htmlBody || "";
  const htmlBody = (() => {
    const normalized = originalHtml.replace(/\r\n/g, "\n");
    if (!normalized.trim()) return "";
<<<<<<< HEAD
    const looksLikeHtml = /<\/?[a-z][\s\S]*>/i.test(normalized);
    if (looksLikeHtml) return normalized;
    return normalized.split("\n").map((line) => line || "<br>").join("<br>");
  })();
  const textBodyRaw =
    job.textBody && job.textBody.trim().length
      ? job.textBody
      : htmlBody
        ? stripHtml(htmlBody)
        : "";
  const textBody = textBodyRaw.replace(/\r\n/g, "\n");
  const attachments = normalizeJobAttachments(job).map((att) => ({
    filename: att.filename,
    content: att.buffer.toString("base64"),
  }));
  const maxRequestsPerSecond = normalizeResendRequestsPerSecond(
    config.maxRequestsPerSecond || config.requestsPerSecond
  );

  const results = {
    sent: 0,
    failed: 0,
    errorDetails: [],
  };

=======
    if (/<\/?[a-z][\s\S]*>/i.test(normalized)) return normalized;
    return normalized.split("\n").map((line) => line || "<br>").join("<br>");
  })();
  const textBodyRaw = job.textBody && job.textBody.trim().length ? job.textBody : htmlBody ? stripHtml(htmlBody) : "";
  const textBody = textBodyRaw.replace(/\r\n/g, "\n");
  const attachments = normalizeJobAttachments(job).map((att) => {
    if (att.content) return { filename: att.filename, content: att.content.toString("base64") };
    if (att.url) return { filename: att.filename, path: att.url };
    return null;
  }).filter(Boolean);
  const maxRequestsPerSecond = normalizeResendRequestsPerSecond(config.maxRequestsPerSecond || config.requestsPerSecond);
  const results = { sent: 0, failed: 0, errorDetails: [] };
>>>>>>> f8d4db3c (New updates.)
  for (const address of batch) {
    let delivered = false;
    let attempt = 0;
    while (!delivered && attempt <= RESEND_RATE_RETRY_MAX_ATTEMPTS) {
      await throttleResendRequest(maxRequestsPerSecond);
      try {
        const response = await resend.emails.send({
          from,
          to: [address],
          subject: job.subject || "",
          html: htmlBody || undefined,
          text: textBody || undefined,
          replyTo: job.replyTo || config.replyTo || undefined,
          attachments: attachments.length ? attachments : undefined,
        });
        if (response?.error) {
          if (isResendRateLimitError(response.error) && attempt < RESEND_RATE_RETRY_MAX_ATTEMPTS) {
            attempt += 1;
            await new Promise((resolve) => setTimeout(resolve, RESEND_RATE_RETRY_DELAY_MS * attempt));
            continue;
          }
<<<<<<< HEAD
          const message = response.error.message || "Resend API request failed";
          results.failed += 1;
          results.errorDetails.push({
            recipient: address,
            message,
            response: response.error,
          });
=======
          results.failed += 1;
          results.errorDetails.push({ recipient: address, message: response.error.message || "Resend API request failed", response: response.error });
>>>>>>> f8d4db3c (New updates.)
          break;
        }
        results.sent += 1;
        delivered = true;
      } catch (err) {
        if (isResendRateLimitError(err) && attempt < RESEND_RATE_RETRY_MAX_ATTEMPTS) {
          attempt += 1;
          await new Promise((resolve) => setTimeout(resolve, RESEND_RATE_RETRY_DELAY_MS * attempt));
          continue;
        }
        results.failed += 1;
<<<<<<< HEAD
        results.errorDetails.push({
          recipient: address,
          message: err.message,
        });
=======
        results.errorDetails.push({ recipient: address, message: err.message });
>>>>>>> f8d4db3c (New updates.)
        break;
      }
    }
  }
<<<<<<< HEAD

=======
>>>>>>> f8d4db3c (New updates.)
  return {
    success: results.failed === 0,
    sent: results.sent,
    failed: results.failed,
    recipients: batch,
    transport: "resend",
    error: results.failed ? results.errorDetails[0]?.message : undefined,
    errorDetails: results.errorDetails,
  };
}

<<<<<<< HEAD
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
  const data = await loadAuthStore();
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
=======
async function sendBatchWithSmtp(job, batch, smtpServer, proxyUrl) {
  const port = parseInt(smtpServer.port || "587", 10);
  const fromEmail = smtpServer.from || smtpServer.username;
  const fromAddress = formatFromAddress(job.fromName || job.from || smtpServer.label, fromEmail);
  const replyToAddress = job.replyTo ? formatFromAddress(undefined, job.replyTo) : formatFromAddress(job.fromName || job.from, fromEmail);
  const transportOptions = {
    host: smtpServer.host,
    port,
    secure: port === 465,
    auth: { user: smtpServer.username, pass: smtpServer.password },
    connectionTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    greetingTimeout: SMTP_CONNECTION_TIMEOUT_MS,
    socketTimeout: SMTP_SOCKET_TIMEOUT_MS,
  };
  if (proxyUrl) {
    if (proxyUrl.startsWith("socks")) transportOptions.agent = new SocksProxyAgent(proxyUrl);
    else transportOptions.proxy = proxyUrl;
  }
  const transporter = nodemailer.createTransport(transportOptions);
  let sent = 0;
  let failed = 0;
  const errors = [];
  const errorDetails = [];
  const attachments = normalizeJobAttachments(job).map((att) => {
    if (att.content) return { filename: att.filename, content: att.content, contentType: att.contentType };
    if (att.url) return { filename: att.filename, path: att.url, contentType: att.contentType };
    return null;
  }).filter(Boolean);
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
      errorDetails.push({ recipient, message: err.message, code: err && (err.responseCode || err.code), command: err && err.command, response: err && err.response });
      console.error(`SMTP send failure (${smtpServer.label || smtpServer.username} -> ${recipient}):`, err.responseCode || err.code, err.response || err.message);
    }
  }
  return {
    success: failed === 0, sent, failed, recipients: batch, smtpId: smtpServer.id || smtpServer.username, smtpLabel: smtpServer.label, transport: "smtp", error: errors[0], errorDetails,
  };
}

async function dispatchWithProvider(provider, job, batch) {
  const type = provider.type || "resend";
  const config = provider.config || {};
  if (type === "resend") return sendBatchWithResend(job, batch, config);
  if (type === "smtp") {
    const smtpConfig = { ...config, label: config.label || provider.name, from: config.from || config.fromAddress };
    return sendBatchWithSmtp(job, batch, smtpConfig, config.proxy);
  }
  return { success: false, sent: 0, failed: batch.length, recipients: batch, transport: type, error: `Unsupported provider type ${type}`, errorDetails: [{ message: `Unsupported provider type ${type}` }] };
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

async function sendEmailJob(job) {
  const recipientsRaw = await loadRecipients(job);
  if (!recipientsRaw.length) throw new Error("This job does not have any recipients to send to.");
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
    const invalidDetails = invalidRecipients.map((recipient) => ({ recipient, message: "Invalid email address", code: "INVALID_RECIPIENT" }));
    results.push({ success: false, sent: 0, failed: invalidRecipients.length, recipients: invalidRecipients, transport: "validation", error: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}`, errorDetails: invalidDetails });
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
        throw new Error("No eligible enabled provider is currently available. Check provider quotas, enabled state, and credentials.");
      }
      const smtpPoolAvailable = await hasConfiguredSmtpPool();
      if (smtpPoolAvailable) {
        const proxy = await getNextProxy();
        const smtpServer = await resolveSmtpServerForBatch(job);
        const smtpResult = await sendBatchWithSmtp(job, batch, smtpServer, proxy);
        if (smtpServer?.__fromPool) await recordSmtpUsage(smtpResult.sent || batch.length);
        results.push({ ...smtpResult, proxy });
        sentTotal += smtpResult.sent;
        failedTotal += smtpResult.failed;
      } else {
        throw new Error("No enabled mail providers configured. Add a Resend (or SMTP) provider in Admin > API & SMTP Providers.");
      }
      if (job.delayBetweenBatches) await new Promise((resolve) => setTimeout(resolve, job.delayBetweenBatches * 1000));
    } catch (err) {
      results.push({ success: false, error: err.message, recipients: batch });
      failedTotal += batch.length;
    }
  }
  return { success: failedTotal === 0, sent: sentTotal, failed: failedTotal, results };
}

async function dispatchJob(job, payload, { skipRateLimit = false } = {}) {
  job.status = "sending";
  job.updatedAt = new Date().toISOString();
  await saveJob(job);

  if (!skipRateLimit) {
    const allowed = await checkEmailRateLimit(job.owner);
    if (!allowed) {
      const errMsg = `Email rate limit exceeded. Maximum ${EMAIL_RATE_LIMIT} emails per minute.`;
      job.status = "failed";
      job.error = errMsg;
      job.updatedAt = new Date().toISOString();
      await saveJob(job);
      await recordActivity(job, null, errMsg, null);
      const rateErr = new Error(errMsg);
      rateErr.statusCode = 429;
      throw rateErr;
    }
  }

  // Deduct credits
  const recipientsRaw = await loadRecipients(job);
  const { valid: recipients } = splitRecipientList(recipientsRaw);
  const userCredits = await getUserCredits(job.owner);
  const cost = userCredits.costPerEmail * recipients.length;
  const canDeduct = await deductCredits(job.owner, cost);
  if (!canDeduct) {
    const errMsg = `Insufficient credits. You need ${cost} credits but have ${userCredits.credits}.`;
    job.status = "failed";
    job.error = errMsg;
    job.updatedAt = new Date().toISOString();
    await saveJob(job);
    await recordActivity(job, null, errMsg, null);
    const err = new Error(errMsg);
    err.statusCode = 402;
    throw err;
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
    if (transportMeta.lastTransport) job.lastTransport = transportMeta.lastTransport;
    else if (!job.lastTransport) job.lastTransport = "resend";
    if (transportMeta.lastProvider) job.lastProviderSnapshot = transportMeta.lastProvider;
    if (transportMeta.transports?.length) job.transportHistory = mergeTransportHistory(job.transportHistory, transportMeta.transports);
    const failureMsg = extractResultError(result);
    if (!result.success && failureMsg) job.error = failureMsg;
    else delete job.error;
    job.updatedAt = new Date().toISOString();
    await saveJob(job);
    await recordActivity(job, result, null, transportMeta);
    return result;
  } catch (err) {
    // Refund credits on send failure
    await deductCredits(job.owner, -cost);
    job.status = "failed";
    job.error = err.message;
    job.updatedAt = new Date().toISOString();
    await saveJob(job);
    await recordActivity(job, null, err.message, null);
    throw err;
  }
}

// ---------- Auth Routes ----------
app.post("/auth/login", async (req, res) => {
  const { username = "", password = "" } = req.body || {};
  if (!username || !password) return res.status(400).json({ message: "Username and password are required" });
  const user = await findUserByUsername(username);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  const expected = hashPassword(password, user.salt);
  if (expected !== user.passwordHash) return res.status(401).json({ message: "Invalid credentials" });
  if ((user.status || "active") === "suspended") return res.status(403).json({ message: "Account suspended" });
  const token = uuid();
  sessions.set(token, { token, username: user.username, role: user.role || "user", id: user.id, expiresAt: Date.now() + SESSION_TIMEOUT_SECONDS * 1000 });
  res.json({ token, username: user.username, role: user.role || "user", mailboxes: user.mailboxes || [], status: user.status || "active", credits: user.credits || 0, creditsUsed: user.creditsUsed || 0, costPerEmail: user.costPerEmail || DEFAULT_COST_PER_EMAIL, features: user.features || {} });
>>>>>>> f8d4db3c (New updates.)
});

app.post("/auth/logout", requireAuth, (req, res) => {
  const token = extractToken(req);
  if (token) sessions.delete(token);
  res.json({ message: "Logged out" });
});

app.get("/auth/me", requireAuth, async (req, res) => {
<<<<<<< HEAD
  const data = await loadAuthStore();
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
=======
  const user = await findUserByUsername(req.user.username);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ username: user.username, role: user.role || "user", mailboxes: user.mailboxes || [], status: user.status || "active", credits: user.credits || 0, creditsUsed: user.creditsUsed || 0, costPerEmail: user.costPerEmail || DEFAULT_COST_PER_EMAIL, features: user.features || {} });
});

// ---------- Admin: Users ----------
>>>>>>> f8d4db3c (New updates.)
app.get("/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  const { users = [] } = await loadAuthStore();
  res.json(users.map((u) => sanitizeUserForResponse(u)));
});

app.post("/admin/users", requireAuth, requireAdmin, async (req, res) => {
<<<<<<< HEAD
  const { username = "", password = "", role = "user", status = "active" } = req.body || {};
  const usernameValue = String(username || "").trim();
  const passwordValue = String(password || "");
  if (!usernameValue || !passwordValue) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  const payload = await loadAuthStore();
  const usernameKey = usernameValue.toLowerCase();
  if ((payload.users || []).some((u) => String(u.username || "").toLowerCase() === usernameKey)) {
    return res.status(409).json({ message: "Username already exists" });
  }
=======
  const { username = "", password = "", role = "user", status = "active", credits, costPerEmail, features } = req.body || {};
  const usernameValue = String(username || "").trim();
  const passwordValue = String(password || "");
  if (!usernameValue || !passwordValue) return res.status(400).json({ message: "Username and password are required" });
  const existing = await findUserByUsername(usernameValue);
  if (existing) return res.status(409).json({ message: "Username already exists" });
>>>>>>> f8d4db3c (New updates.)
  const salt = cryptoSalt();
  const now = new Date().toISOString();
  const newUser = {
    id: uuid(),
    username: usernameValue,
    passwordHash: hashPassword(passwordValue, salt),
    salt,
    role: normalizeUserRole(role),
    status: normalizeUserStatus(status),
    mailboxes: [],
<<<<<<< HEAD
    createdAt: now,
    updatedAt: now,
  };
  payload.users = Array.isArray(payload.users) ? payload.users : [];
  payload.users.push(newUser);
  await saveAuthStore(payload);
=======
    credits: credits !== undefined ? parseInt(credits, 10) : DEFAULT_CREDITS,
    creditsUsed: 0,
    costPerEmail: costPerEmail !== undefined ? parseInt(costPerEmail, 10) : DEFAULT_COST_PER_EMAIL,
    features: features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 },
    createdAt: now,
    updatedAt: now,
  };
  if (db) {
    await db.collection("users").doc(newUser.id).set(newUser);
  } else {
    const payload = await readJsonFallback(authFilePath, { users: [] });
    payload.users = Array.isArray(payload.users) ? payload.users : [];
    payload.users.push(newUser);
    await writeJsonFallback(authFilePath, payload);
  }
>>>>>>> f8d4db3c (New updates.)
  res.status(201).json({ message: "User created successfully", user: sanitizeUserForResponse(newUser) });
});

app.put("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const updates = req.body || {};
<<<<<<< HEAD
  const payload = await loadAuthStore();
  const idx = payload.users.findIndex((u) => u.id === id);
  if (idx === -1) return res.status(404).json({ message: "User not found" });
  const usernameCandidate = updates.username ? String(updates.username).trim() : "";
  if (usernameCandidate && usernameCandidate !== payload.users[idx].username) {
    const usernameKey = usernameCandidate.toLowerCase();
    if (payload.users.some((u) => String(u.username || "").toLowerCase() === usernameKey)) {
      return res.status(409).json({ message: "Username already exists" });
    }
    payload.users[idx].username = usernameCandidate;
  }
  if (updates.role) payload.users[idx].role = normalizeUserRole(updates.role);
  if (updates.status) payload.users[idx].status = normalizeUserStatus(updates.status);
  payload.users[idx].updatedAt = new Date().toISOString();
  await saveAuthStore(payload);
=======
  const user = await findUserById(id);
  if (!user) return res.status(404).json({ message: "User not found" });
  if (updates.username && updates.username !== user.username) {
    const existing = await findUserByUsername(updates.username);
    if (existing) return res.status(409).json({ message: "Username already exists" });
  }
  const updateData = {};
  if (updates.username) updateData.username = updates.username;
  if (updates.role) updateData.role = normalizeUserRole(updates.role);
  if (updates.status) updateData.status = normalizeUserStatus(updates.status);
  if (updates.credits !== undefined) updateData.credits = parseInt(updates.credits, 10);
  if (updates.costPerEmail !== undefined) updateData.costPerEmail = parseInt(updates.costPerEmail, 10);
  if (updates.features) updateData.features = updates.features;
  updateData.updatedAt = new Date().toISOString();
  await updateUserInDb(id, updateData);
>>>>>>> f8d4db3c (New updates.)
  res.json({ message: "User updated successfully" });
});

app.delete("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
  const payload = await loadAuthStore();
  const idx = payload.users.findIndex((u) => u.id === id);
  if (idx === -1) return res.status(404).json({ message: "User not found" });
  const deleted = payload.users.splice(idx, 1)[0];
  await saveAuthStore(payload);
  for (const [token, session] of sessions.entries()) {
    if (session.username === deleted.username) sessions.delete(token);
=======
  const user = await findUserById(id);
  if (!user) return res.status(404).json({ message: "User not found" });
  if (db) {
    await db.collection("users").doc(id).delete();
  } else {
    const payload = await readJsonFallback(authFilePath, { users: [] });
    payload.users = payload.users.filter((u) => u.id !== id);
    await writeJsonFallback(authFilePath, payload);
  }
  for (const [token, session] of sessions.entries()) {
    if (session.username === user.username) sessions.delete(token);
>>>>>>> f8d4db3c (New updates.)
  }
  res.json({ message: "User deleted successfully" });
});

app.post("/admin/users/:id/change-password", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword = "" } = req.body || {};
  if (!newPassword) return res.status(400).json({ message: "New password is required" });
<<<<<<< HEAD
  const payload = await loadAuthStore();
  const user = payload.users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const salt = cryptoSalt();
  user.salt = salt;
  user.passwordHash = hashPassword(newPassword, salt);
  user.updatedAt = new Date().toISOString();
  await saveAuthStore(payload);
  res.json({ message: "Password updated successfully" });
});

// ---------- Admin SMTP pool ----------
=======
  const user = await findUserById(id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const salt = cryptoSalt();
  await updateUserInDb(id, { salt, passwordHash: hashPassword(newPassword, salt), updatedAt: new Date().toISOString() });
  res.json({ message: "Password updated successfully" });
});

// ---------- Admin: Credits Management ----------
app.get("/admin/credits", requireAuth, requireAdmin, async (_req, res) => {
  const { users = [] } = await loadAuthStore();
  const creditData = users.map((u) => ({
    id: u.id,
    username: u.username,
    credits: u.credits || 0,
    creditsUsed: u.creditsUsed || 0,
    costPerEmail: u.costPerEmail || DEFAULT_COST_PER_EMAIL,
    features: u.features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 },
  }));
  res.json(creditData);
});

app.put("/admin/users/:id/credits", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { credits, costPerEmail } = req.body || {};
  const user = await findUserById(id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const updateData = { updatedAt: new Date().toISOString() };
  if (credits !== undefined) updateData.credits = parseInt(credits, 10);
  if (costPerEmail !== undefined) updateData.costPerEmail = parseInt(costPerEmail, 10);
  await updateUserInDb(id, updateData);
  res.json({ message: "Credits updated" });
});

app.put("/admin/users/:id/features", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { features } = req.body || {};
  if (!features) return res.status(400).json({ message: "Features object required" });
  const user = await findUserById(id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const existingFeatures = user.features || {};
  const mergedFeatures = { ...existingFeatures, ...features };
  await updateUserInDb(id, { features: mergedFeatures, updatedAt: new Date().toISOString() });
  res.json({ message: "Features updated", features: mergedFeatures });
});

// ---------- Admin: SMTP Pool ----------
>>>>>>> f8d4db3c (New updates.)
app.get("/admin/smtp", requireAuth, requireAdmin, async (_req, res) => {
  const pool = await loadSmtpPool();
  res.json({ ...pool, servers: (pool.servers || []).map((server) => sanitizeSmtp(server)) });
});

app.post("/admin/smtp", requireAuth, requireAdmin, async (req, res) => {
  const { label = "", from = "", host = "", port, username = "", password = "", rotateAfter } = req.body || {};
<<<<<<< HEAD
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
=======
  if (!host || !username || !password) return res.status(400).json({ message: "host, username, and password are required" });
  const pool = await loadSmtpPool();
  const now = new Date().toISOString();
  const server = { id: uuid(), label: label || username, from: from || username, host: host.trim(), port: parseInt(port || "587", 10), username: username.trim(), password, createdAt: now, updatedAt: now };
  pool.servers.push(server);
  if (rotateAfter !== undefined) { pool.rotateAfter = normalizeRotateAfter(rotateAfter); pool.sentSinceRotation = 0; }
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (updates.rotateAfter !== undefined) {
    pool.rotateAfter = normalizeRotateAfter(updates.rotateAfter);
    pool.sentSinceRotation = 0;
  }
=======
  if (updates.rotateAfter !== undefined) { pool.rotateAfter = normalizeRotateAfter(updates.rotateAfter); pool.sentSinceRotation = 0; }
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (pool.currentIndex >= pool.servers.length) {
    pool.currentIndex = 0;
    pool.sentSinceRotation = 0;
  }
=======
  if (pool.currentIndex >= pool.servers.length) { pool.currentIndex = 0; pool.sentSinceRotation = 0; }
>>>>>>> f8d4db3c (New updates.)
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

<<<<<<< HEAD
// ---------- IP rotation & rate limits ----------
app.get("/admin/ip-rotation", requireAuth, requireAdmin, async (_req, res) => {
  const data = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
=======
// ---------- Admin: IP Rotation & Rate Limits ----------
app.get("/admin/ip-rotation", requireAuth, requireAdmin, async (_req, res) => {
  const data = await readIpRotation();
>>>>>>> f8d4db3c (New updates.)
  res.json(data);
});

app.post("/admin/ip-rotation", requireAuth, requireAdmin, async (req, res) => {
  const { proxies = [] } = req.body || {};
  if (!Array.isArray(proxies)) return res.status(400).json({ message: "Proxies must be an array" });
<<<<<<< HEAD
  const payload = {
    proxies: proxies.map((p) => String(p).trim()).filter(Boolean),
    currentIndex: 0,
    updatedAt: new Date().toISOString(),
  };
  await writeJson(ipRotationFilePath, payload);
=======
  const payload = { proxies: proxies.map((p) => String(p).trim()).filter(Boolean), currentIndex: 0, updatedAt: new Date().toISOString() };
  await writeIpRotation(payload);
>>>>>>> f8d4db3c (New updates.)
  res.json({ message: "IP rotation configuration updated", proxies: payload.proxies.length });
});

app.get("/admin/rate-limits", requireAuth, requireAdmin, async (_req, res) => {
<<<<<<< HEAD
  const data = await readJson(rateLimitFilePath, { limits: {} });
=======
  const data = await readRateLimits();
>>>>>>> f8d4db3c (New updates.)
  res.json(data);
});

app.post("/admin/rate-limits/reset", requireAuth, requireAdmin, async (req, res) => {
  const { username } = req.body || {};
<<<<<<< HEAD
  const data = await readJson(rateLimitFilePath, { limits: {} });
  if (username) {
    delete data.limits[username];
  } else {
    data.limits = {};
  }
  await writeJson(rateLimitFilePath, data);
=======
  const data = await readRateLimits();
  if (username) delete data.limits[username];
  else data.limits = {};
  await writeRateLimits(data);
>>>>>>> f8d4db3c (New updates.)
  res.json({ message: "Rate limits reset successfully" });
});

app.get("/admin/settings", requireAuth, requireAdmin, async (_req, res) => {
  const settings = await readAppSettings();
  res.json(settings);
});

app.post("/admin/settings", requireAuth, requireAdmin, async (req, res) => {
  const { paymentDetails, telegramLink, tokenRate } = req.body || {};
  const settings = await readAppSettings();
  if (paymentDetails !== undefined) settings.paymentDetails = String(paymentDetails);
  if (telegramLink !== undefined) settings.telegramLink = String(telegramLink);
  if (tokenRate !== undefined) settings.tokenRate = Number(tokenRate) || 10;
  settings.updatedAt = new Date().toISOString();
  await saveAppSettings(settings);
  res.json({ message: "Settings saved", settings });
});

app.post("/admin/data-sync", requireAuth, requireAdmin, async (req, res) => {
  const { message = "", push = true } = req.body || {};
  try {
    const result = syncDataRepo({ message, push: push !== false });
<<<<<<< HEAD
    const text = result.changed
      ? `Data committed${result.pushed ? " and pushed" : ""}.`
      : "No changes detected.";
=======
    const text = result.changed ? `Data committed${result.pushed ? " and pushed" : ""}.` : "No changes detected.";
>>>>>>> f8d4db3c (New updates.)
    res.json({ message: text, ...result });
  } catch (err) {
    const logs = err.gitLogs || [];
    res.status(500).json({ message: err.message || "Failed to sync data", logs });
  }
});

<<<<<<< HEAD
<<<<<<< HEAD
// ---------- Jobs ----------
app.get("/api/jobs", requireAuth, async (req, res) => {
  const { jobs = [] } = await readJson(jobsFilePath, { jobs: [] });
=======
=======
app.post("/admin/sync-to-firebase", requireAuth, requireAdmin, async (req, res) => {
  if (!db) return res.status(400).json({ message: "Firebase is not configured or not connected. Set FIREBASE_* env vars." });
  try {
    const results = { users: 0, jobs: 0, recipients: 0, smtpPool: false, ipRotation: false, rateLimits: false, mailProviders: false, activity: 0, errors: [] };

    // Sync users
    const authData = await readJsonFallback(authFilePath, { users: [] });
    const users = authData.users || [];
    for (const user of users) {
      const id = user.id || uuid();
      await db.collection("users").doc(id).set(user, { merge: true });
      results.users++;
    }

    // Sync jobs
    const jobsData = await readJsonFallback(jobsFilePath, { jobs: [] });
    const jobs = jobsData.jobs || [];
    for (const job of jobs) {
      const id = job.id || uuid();
      job.id = id;
      await db.collection("jobs").doc(id).set(job, { merge: true });
      results.jobs++;
    }

    // Sync job recipients
    const recipientFiles = await fs.readdir(recipientsDir).catch(() => []);
    for (const file of recipientFiles) {
      if (!file.endsWith(".json")) continue;
      const jobId = file.replace(".json", "");
      const data = await readJsonFallback(path.join(recipientsDir, file), { recipients: [] });
      if (Array.isArray(data.recipients) && data.recipients.length) {
        await db.collection("jobRecipients").doc(jobId).set(data);
        results.recipients += data.recipients.length;
      }
    }

    // Sync smtp pool
    const smtpData = await readJsonFallback(smtpPoolFilePath, { servers: [], currentIndex: 0, sentSinceRotation: 0, rotateAfter: SMTP_ROTATE_AFTER_DEFAULT });
    await db.collection("config").doc("smtpPool").set(smtpData);
    results.smtpPool = true;

    // Sync mail providers
    const providerData = await readJsonFallback(mailProvidersFilePath, { providers: [], rotationIndex: 0 });
    await db.collection("config").doc("mailProviders").set(providerData);
    results.mailProviders = true;

    // Sync ip rotation
    const ipData = await readJsonFallback(ipRotationFilePath, { proxies: [], currentIndex: 0 });
    await db.collection("config").doc("ipRotation").set(ipData);
    results.ipRotation = true;

    // Sync rate limits
    const rateData = await readJsonFallback(rateLimitFilePath, { limits: {} });
    await db.collection("config").doc("rateLimits").set(rateData);
    results.rateLimits = true;

    // Sync activity log
    const activityData = await readJsonFallback(activityLogPath, { entries: [] });
    const entries = activityData.entries || [];
    for (const entry of entries) {
      await db.collection("activity").add(entry);
      results.activity++;
    }

    res.json({ message: "Sync to Firebase complete", results });
  } catch (err) {
    res.status(500).json({ message: err.message || "Sync failed" });
  }
});

>>>>>>> 102efad6 (feat: implement app settings management, migrate file uploads to tmpfiles.org, and add Firebase sync utilities)
function runGitCommand(command, logs, { allowFailure = false } = {}) {
  const entry = { command };
  try {
    const stdout = execSync(command, { cwd: rootDir, stdio: ["ignore", "pipe", "pipe"] });
    entry.stdout = stdout.toString().trim();
    logs.push(entry);
    return entry.stdout || "";
  } catch (err) {
    entry.stdout = err.stdout ? err.stdout.toString().trim() : "";
    entry.stderr = err.stderr ? err.stderr.toString().trim() : err.message;
    entry.failed = true;
    logs.push(entry);
    if (allowFailure) return entry.stdout || entry.stderr || "";
    const error = new Error(entry.stderr || entry.stdout || err.message);
    error.gitLogs = logs;
    throw error;
  }
}

function syncDataRepo({ message, push }) {
  const logs = [];
  const statusOutput = runGitCommand("git status --porcelain data", logs, { allowFailure: true });
  if (!statusOutput.trim()) return { changed: false, pushed: false, logs };
  runGitCommand("git add data", logs);
  const commitMessage = String(message || "").trim() || DATA_SYNC_DEFAULT_MESSAGE;
  runGitCommand(`git commit -m ${JSON.stringify(commitMessage)}`, logs);
  let pushed = false;
  if (push) { runGitCommand("git push", logs); pushed = true; }
  return { changed: true, pushed, commitMessage, logs };
}

// ---------- Admin: Jobs ----------
app.get("/api/jobs", requireAuth, async (req, res) => {
  const jobs = await loadJobsCollection();
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
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
  const users = (await loadAuthStore()).users || [];
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
=======
    subject = "", fromName = "", from = "", replyTo = "", textBody = "", htmlBody = "",
    recipients, attachments = [], batchSize, delayBetweenBatches = 2, maxRetries = 3,
  } = req.body || {};
  if (!subject || !fromName) return res.status(400).json({ message: "fromName and subject are required" });
  const recipientListRaw = normalizeRecipients(recipients);
  if (!recipientListRaw.length) return res.status(400).json({ message: "At least one recipient is required" });
  const { valid: recipientList, invalid: invalidRecipients } = splitRecipientList(recipientListRaw);
  if (!recipientList.length) return res.status(400).json({ message: invalidRecipients.length ? `All recipients are invalid. Please fix: ${invalidRecipients.slice(0, 5).join(", ")}` : "At least one valid recipient is required" });
  if (invalidRecipients.length) return res.status(400).json({ message: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}` });
  const owner = req.user.role === "admin" && req.body.owner ? req.body.owner : req.user.username;
  const user = await findUserByUsername(owner);
  if (!user) return res.status(400).json({ message: `Unknown owner ${owner}` });
  const now = new Date().toISOString();
  const job = {
    id: uuid(), owner, subject, fromName, from: from || undefined, replyTo: replyTo || undefined,
    textBody, htmlBody, recipientsCount: recipientList.length,
>>>>>>> f8d4db3c (New updates.)
    recipientsPreview: recipientList.slice(0, 5),
    batchSize: parseInt(batchSize || BATCH_SIZE_DEFAULT, 10),
    delayBetweenBatches: parseInt(delayBetweenBatches, 10),
    maxRetries: parseInt(maxRetries, 10),
<<<<<<< HEAD
    attachments: storedAttachments,
    status: "pending",
    transportHint: MAIL_TRANSPORT,
    createdAt: now,
    updatedAt: now,
  };
  payload.jobs.push(job);
  await writeJson(jobsFilePath, payload);
  await saveRecipients(job.id, recipientList);
=======
    attachments: Array.isArray(attachments) ? attachments : [],
    status: "pending", transportHint: "resend", createdAt: now, updatedAt: now,
  };
  await saveJob(job);
  await saveRecipientsToDb(job.id, recipientList);
>>>>>>> f8d4db3c (New updates.)
  res.status(201).json(job);
});

app.get("/api/jobs/:id/recipients", requireAuth, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot access this job" });
  }
=======
  const job = await findJobById(id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) return res.status(403).json({ message: "You cannot access this job" });
>>>>>>> f8d4db3c (New updates.)
  const recipients = await loadRecipients(job);
  res.json({ recipients });
});

app.put("/api/jobs/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
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
=======
  const { subject = "", fromName = "", replyTo = "", textBody = "", htmlBody = "", recipients, attachments, batchSize, delayBetweenBatches = 2, maxRetries = 3 } = req.body || {};
  if (!subject || !fromName) return res.status(400).json({ message: "fromName and subject are required" });
  const job = await findJobById(id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) return res.status(403).json({ message: "You cannot edit this job" });
  const recipientListRaw = normalizeRecipients(recipients);
  if (!recipientListRaw.length) return res.status(400).json({ message: "At least one recipient is required" });
  const { valid: recipientList, invalid: invalidRecipients } = splitRecipientList(recipientListRaw);
  if (!recipientList.length) return res.status(400).json({ message: invalidRecipients.length ? `All recipients are invalid. Please fix: ${invalidRecipients.slice(0, 5).join(", ")}` : "At least one valid recipient is required" });
  if (invalidRecipients.length) return res.status(400).json({ message: `Invalid recipient(s): ${invalidRecipients.slice(0, 5).join(", ")}` });
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (!job.transportHint) {
    job.transportHint = MAIL_TRANSPORT;
  }
  if (attachments !== undefined) {
    job.attachments = normalizeAttachmentPayloadForStorage(attachments);
  } else if (!Array.isArray(job.attachments)) {
    job.attachments = [];
  }
=======
  if (!job.transportHint) job.transportHint = "resend";
  if (attachments !== undefined) job.attachments = Array.isArray(attachments) ? attachments : [];
  else if (!Array.isArray(job.attachments)) job.attachments = [];
>>>>>>> f8d4db3c (New updates.)
  job.updatedAt = new Date().toISOString();
  job.status = "pending";
  delete job.lastResult;
  delete job.lastSentAt;
  job.sentCount = 0;
  job.failedCount = 0;
  delete job.error;
<<<<<<< HEAD
  await writeJson(jobsFilePath, payload);
  await saveRecipients(job.id, recipientList);
=======
  await saveJob(job);
  await saveRecipientsToDb(job.id, recipientList);
>>>>>>> f8d4db3c (New updates.)
  res.json(job);
});

app.delete("/api/jobs/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const idx = payload.jobs.findIndex(
    (job) => job.id === id && (req.user.role === "admin" || job.owner === req.user.username)
  );
  if (idx === -1) return res.status(404).json({ message: "Job not found" });
  const removed = payload.jobs.splice(idx, 1)[0];
  await writeJson(jobsFilePath, payload);
  await fs.remove(recipientsFile(id));
  res.json({ message: "Job deleted", job: removed });
=======
  const job = await findJobById(id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) return res.status(403).json({ message: "Cannot delete this job" });
  await deleteJobFromDb(id);
  await deleteRecipientsFromDb(id);
  res.json({ message: "Job deleted" });
>>>>>>> f8d4db3c (New updates.)
});

app.post("/api/jobs/:id/send", requireAuth, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
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
=======
  const job = await findJobById(id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) return res.status(403).json({ message: "You cannot trigger this job" });
  if (job.status === "sending") return res.status(409).json({ message: "Job is already sending" });
  try {
    const result = await dispatchJob(job, null);
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
  if (req.user.role !== "admin") {
    entries = entries.filter((entry) => entry.owner === req.user.username);
  } else if (owner) {
    entries = entries.filter((entry) => entry.owner === owner);
  }
=======
  if (req.user.role !== "admin") entries = entries.filter((entry) => entry.owner === req.user.username);
  else if (owner) entries = entries.filter((entry) => entry.owner === owner);
>>>>>>> f8d4db3c (New updates.)
  const size = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  res.json(entries.slice(0, size));
});

app.delete("/admin/jobs/:id/recipients", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
<<<<<<< HEAD
  const payload = await readJson(jobsFilePath, { jobs: [] });
  const job = payload.jobs.find((j) => j.id === id);
=======
  const job = await findJobById(id);
>>>>>>> f8d4db3c (New updates.)
  if (!job) return res.status(404).json({ message: "Job not found" });
  const { recipientsCount = 0 } = await loadRecipientsPreview(id);
  job.recipientsCount = 0;
  job.recipientsPreview = [];
  job.recipients = [];
  job.updatedAt = new Date().toISOString();
<<<<<<< HEAD
  await writeJson(jobsFilePath, payload);
  await fs.remove(recipientsFile(id));
=======
  await saveJob(job);
  await deleteRecipientsFromDb(id);
>>>>>>> f8d4db3c (New updates.)
  res.json({ message: "Recipient log cleared", removed: recipientsCount });
});

app.post("/api/jobs/:id/replay", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { skipRateLimit = false } = req.body || {};
<<<<<<< HEAD
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
=======
  const job = await findJobById(id);
  if (!job) return res.status(404).json({ message: "Job not found" });
  if (req.user.role !== "admin" && job.owner !== req.user.username) return res.status(403).json({ message: "You cannot replay this job" });
  try {
    resetJobForReplay(job);
    const replayResult = await dispatchJob(job, null, { skipRateLimit: Boolean(skipRateLimit) });
    res.json({ message: "Job replay complete", job, result: replayResult });
>>>>>>> f8d4db3c (New updates.)
  } catch (err) {
    const status = err.statusCode || 500;
    res.status(status).json({ message: err.message || "Failed to replay job" });
  }
});

app.post("/admin/jobs/replay", requireAuth, requireAdmin, async (req, res) => {
<<<<<<< HEAD
  const {
    transport = "resend",
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
    includeUnknown !== undefined ? Boolean(includeUnknown) : transport === "resend";
  if (transport) {
    candidates = candidates.filter((job) => {
      const storedTransport = storedJobTransport(job);
      if (storedTransport) return storedTransport === transport;
=======
  const { transport = "resend", statuses, limit, dryRun = false, sort = "asc", includeUnknown } = req.body || {};
  let jobs = await loadJobsCollection();
  const normalizedStatuses = (Array.isArray(statuses) && statuses.length ? statuses : ["sent"]).map((s) => String(s || "").toLowerCase());
  let candidates = jobs.filter((job) => normalizedStatuses.includes(String(job.status || "").toLowerCase()));
  const includeUnknownTransports = includeUnknown !== undefined ? Boolean(includeUnknown) : transport === "resend";
  if (transport) {
    candidates = candidates.filter((job) => {
      const st = storedJobTransport(job);
      if (st) return st === transport;
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
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
=======
  if (!selected.length) return res.json({ message: "No jobs matched filter", matched: candidates.length, processed: 0, results: [] });
  if (dryRun) {
    return res.json({
      message: `Dry run: ${selected.length} job(s) would be replayed`,
      matched: candidates.length, processed: 0,
      results: selected.map((job) => ({ id: job.id, subject: job.subject, status: job.status, transport: storedJobTransport(job) || determineJobTransport(job), recipientsCount: job.recipientsCount || 0 })),
>>>>>>> f8d4db3c (New updates.)
    });
  }
  const results = [];
  for (const job of selected) {
    try {
<<<<<<< HEAD
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
  const users = (await loadAuthStore()).users || [];
  const jobsRaw = (await readJson(jobsFilePath, { jobs: [] })).jobs || [];
  const jobs = await Promise.all(
    jobsRaw.map(async (job) => {
=======
      resetJobForReplay(job);
      const replayResult = await dispatchJob(job, null, { skipRateLimit: true });
      results.push({ id: job.id, subject: job.subject, sent: replayResult.sent, failed: replayResult.failed, transport: job.lastTransport || storedJobTransport(job) || determineJobTransport(job), status: job.status });
    } catch (err) {
      results.push({ id: job.id, subject: job.subject, transport: storedJobTransport(job) || determineJobTransport(job), error: err.message });
    }
  }
  res.json({ message: "Replay completed", matched: candidates.length, processed: selected.length, results });
});

// ---------- Admin: Overview ----------
app.get("/admin/overview", requireAuth, requireAdmin, async (_req, res) => {
  const { users = [] } = await loadAuthStore();
  let jobs = await loadJobsCollection();
  jobs = await Promise.all(
    jobs.map(async (job) => {
>>>>>>> f8d4db3c (New updates.)
      const { recipientsPreview, recipientsCount } = await loadRecipientsPreview(job.id, 5, job.recipients);
      return { ...job, recipientsPreview, recipientsCount };
    })
  );
<<<<<<< HEAD
  const ipData = await readJson(ipRotationFilePath, { proxies: [], currentIndex: 0 });
  const rateLimits = await readJson(rateLimitFilePath, { limits: {} });
=======
  const ipData = await readIpRotation();
  const rateLimitsData = await readRateLimits();
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
    activeRateLimits: Object.keys(rateLimits.limits || {}).length,
    smtpServers: sanitizedSmtpPool.servers.length,
  };
  res.json({ users, jobs, ipRotation: ipData, rateLimits, smtpPool: sanitizedSmtpPool, stats });
});

=======
    activeRateLimits: Object.keys(rateLimitsData.limits || {}).length,
    smtpServers: sanitizedSmtpPool.servers.length,
  };
  res.json({ users: users.map((u) => sanitizeUserForResponse(u)), jobs, ipRotation: ipData, rateLimits: rateLimitsData, smtpPool: sanitizedSmtpPool, stats });
});

// ---------- Admin: Mail Providers ----------
>>>>>>> f8d4db3c (New updates.)
app.get("/admin/providers", requireAuth, requireAdmin, async (_req, res) => {
  const pool = await loadMailProviderPool();
  res.json(pool.providers);
});

app.post("/admin/providers", requireAuth, requireAdmin, async (req, res) => {
  try {
    const payload = sanitizeProviderPayload(req.body || {});
    const error = validateProviderConfig(payload.type, payload.config);
<<<<<<< HEAD
    if (error) {
      return res.status(400).json({ message: error });
    }
=======
    if (error) return res.status(400).json({ message: error });
>>>>>>> f8d4db3c (New updates.)
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
<<<<<<< HEAD
    if (error) {
      return res.status(400).json({ message: error });
    }
=======
    if (error) return res.status(400).json({ message: error });
>>>>>>> f8d4db3c (New updates.)
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
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ---------- File Upload ----------
app.post("/api/upload", requireAuth, async (req, res) => {
  try {
    if (!req.files || !req.files.file) return res.status(400).json({ message: "No file uploaded" });
    const file = req.files.file;
    let result;
    try {
      result = await uploadToTmpFiles(file.data, file.name);
    } catch (cloudErr) {
      console.warn("tmpfiles.org failed, saving locally:", cloudErr.message);
      result = await saveLocalFile(file.data, file.name);
    }
    res.json({ message: "File uploaded", url: result.url, filename: file.name, contentType: file.mimetype || "application/octet-stream", key: result.key });
  } catch (err) {
    res.status(500).json({ message: err.message || "Upload failed" });
  }
});

// ---------- User Settings (payment info, telegram) ----------
app.get("/api/settings", requireAuth, async (_req, res) => {
  const settings = await readAppSettings();
  res.json({
    paymentDetails: settings.paymentDetails || '',
    telegramLink: settings.telegramLink || '',
    tokenRate: settings.tokenRate || 10,
  });
});

// ---------- Health ----------
app.get("/healthz", async (_req, res) => {
  try {
    res.json({ status: "ok", timestamp: new Date().toISOString(), sessionCount: sessions.size, firebase: !!db });
>>>>>>> f8d4db3c (New updates.)
  } catch (err) {
    res.status(500).json({ status: "error", details: err.message });
  }
});

<<<<<<< HEAD
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
        throw new Error(
          "No eligible enabled provider is currently available. Check provider quotas, enabled state, and credentials."
        );
      }
      const smtpPoolAvailable = await hasConfiguredSmtpPool();
      if (MAIL_TRANSPORT === "smtp" || smtpPoolAvailable) {
        const proxy = await getNextProxy();
        const smtpServer = await resolveSmtpServerForBatch(job);
        const smtpResult = await sendBatchWithSmtp(job, batch, smtpServer, proxy);
        if (smtpServer?.__fromPool) {
          await recordSmtpUsage(smtpResult.sent || batch.length);
        }
        results.push({ ...smtpResult, proxy });
        sentTotal += smtpResult.sent;
        failedTotal += smtpResult.failed;
      } else {
        throw new Error(
          "No enabled mail providers configured. Add a Resend (or SMTP) provider in Admin > API & SMTP Providers."
        );
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

=======
>>>>>>> f8d4db3c (New updates.)
// ---------- Static ----------
app.use(express.static(staticDir));

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT} (serving static from ${staticDir})`);
});
