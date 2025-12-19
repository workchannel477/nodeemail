#!/usr/bin/env node
import dotenv from "dotenv";

dotenv.config();

const args = Object.fromEntries(
  process.argv
    .slice(2)
    .map((arg) => {
      if (!arg.startsWith("--")) return [arg, true];
      const [key, ...rest] = arg.replace(/^--/, "").split("=");
      return [key, rest.length ? rest.join("=") : true];
    })
);

const API_BASE =
  args.api ||
  process.env.REPLAY_API_BASE ||
  process.env.API_BASE ||
  "http://localhost:5001";
const ADMIN_USER = args.username || process.env.REPLAY_ADMIN_USER || "admin";
const ADMIN_PASS = args.password || process.env.REPLAY_ADMIN_PASS || "admin123";
const TARGET_TRANSPORT = args.transport || process.env.REPLAY_TRANSPORT || "zoho";
const LIMIT = args.limit || process.env.REPLAY_LIMIT || null;
const DRY_RUN = Boolean(
  args["dry-run"] ||
    args.dryRun ||
    process.env.REPLAY_DRY_RUN === "1" ||
    process.env.REPLAY_DRY_RUN === "true"
);

async function login() {
  const response = await fetch(new URL("/auth/login", API_BASE), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }),
  });
  if (!response.ok) {
    const err = await safeJson(response);
    throw new Error(err.message || `Login failed (${response.status})`);
  }
  return response.json();
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch (err) {
    return {};
  }
}

async function replayJobs(token) {
  const payload = {
    transport: TARGET_TRANSPORT || undefined,
    dryRun: DRY_RUN,
  };
  if (LIMIT) payload.limit = Number(LIMIT);
  const response = await fetch(new URL("/admin/jobs/replay", API_BASE), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });
  const data = await safeJson(response);
  if (!response.ok) {
    throw new Error(data.message || `Replay failed (${response.status})`);
  }
  return data;
}

async function run() {
  try {
    console.log(`Connecting to ${API_BASE} as ${ADMIN_USER}...`);
    const loginResult = await login();
    const token = loginResult.token;
    console.log(
      `Logged in. Triggering replay for transport="${TARGET_TRANSPORT || "any"}"${
        DRY_RUN ? " (dry run)" : ""
      }${LIMIT ? ` limit=${LIMIT}` : ""}.`
    );
    const data = await replayJobs(token);
    console.log(JSON.stringify(data, null, 2));
    process.exit(0);
  } catch (err) {
    console.error("Replay failed:", err.message);
    process.exit(1);
  }
}

run();
