#!/usr/bin/env node
/**
 * Aquarium Game — EBS (Extension Backend Service)
 * ---------------------------------------------------
 * Zero-dependency Node.js (>= 18 for global fetch). Provides the backend the
 * extension needs for production:
 *
 *   • SYNCED SPAWNS — schedules one fish at a time per channel and broadcasts
 *     it to every viewer (spawn / attempt_count / raffle_result / spawn_end
 *     PubSub messages) so everyone sees the same fish at the same time.
 *   • CATCH LIMITS — one global catchLimit applies to every fish (-1 =
 *     unlimited, or a positive number of winners). Limited fish go to a
 *     raffle: everyone who finishes the QTE is entered, and winners are drawn
 *     when the fish leaves. The draw is weighted so faster finishers hold
 *     more tickets — speed raises your odds, it doesn't guarantee the catch.
 *   • BITS VERIFICATION — confirms Bits transactions via the Helix API.
 *   • CHAT POSTS — shares fish in chat with Send Extension Chat Message.
 *   • SHARED LEADERBOARD — stored per channel, broadcast to all viewers.
 *
 * Environment variables:
 *   TWITCH_EXTENSION_ID       (required in production)  = extension Client ID
 *   TWITCH_EXTENSION_SECRET   (required in production)  = extension Client Secret
 *   EXTENSION_VERSION         default "0.0.1"           = must match a hosted/test version
 *   PORT                      default 8081
 *   DATA_DIR                  default ./data
 *   ALLOW_INSECURE=1          dev only: skip JWT verification (no real Twitch calls)
 *
 * Endpoints:
 *   GET  /healthz
 *   GET  /api/leaderboard?channel_id=...
 *   POST /api/hello                       { jwt, channelId, config?, opaqueUserId? }
 *   POST /api/catch                       { jwt, channelId, spawnId, qteMs?, opaqueUserId? }
 *   POST /api/share                       { jwt, channelId, transactionId?, fish }
 *                                          transactionId required unless fish.costBits = 0
 *                                          (free share — posted to chat + leaderboard
 *                                          with no Bits transaction or verification)
 *   POST /api/leaderboard/reset           { jwt, channelId }  (broadcaster only)
 */

"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = parseInt(process.env.PORT, 10) || 8081;
const CLIENT_ID = process.env.TWITCH_EXTENSION_ID || "";
const CLIENT_SECRET = process.env.TWITCH_EXTENSION_SECRET || "";
// Twitch signs viewer/EBS JWTs with the base64-DECODED secret bytes, not the
// base64 string as shown in the console. HMAC with the decoded key.
const SECRET_KEY = CLIENT_SECRET ? Buffer.from(CLIENT_SECRET, "base64") : null;
const EXTENSION_VERSION = process.env.EXTENSION_VERSION || "0.0.1";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const INSECURE = process.env.ALLOW_INSECURE === "1";

const HELIX = "https://api.twitch.tv/helix";
const LIVENESS_MS = 3 * 60 * 1000; // channel considered inactive after 3 min without a hello

if (!CLIENT_ID || !CLIENT_SECRET) {
  if (INSECURE) {
    console.log("WARNING: ALLOW_INSECURE=1 — JWT verification and Twitch calls are DISABLED. Dev/testing only!");
  } else {
    console.error("Set TWITCH_EXTENSION_ID and TWITCH_EXTENSION_SECRET (or ALLOW_INSECURE=1 for local testing).");
    process.exit(1);
  }
}

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------- fallback config (used if a client never sends its config) ---------------- */

const FALLBACK_CONFIG = {
  timer: { minSec: 45, maxSec: 150 },
  spawn: { catchWindowSec: 20, catchLimit: -1 },
  rarities: {
    bronze: { label: "Bronze", color: "#cd7f32", multiplier: 1, qteCircles: 3, qteTime: 8 },
    silver: { label: "Silver", color: "#c0c0c0", multiplier: 2, qteCircles: 4, qteTime: 7 },
    gold: { label: "Gold", color: "#ffd700", multiplier: 3, qteCircles: 5, qteTime: 6 },
    diamond: { label: "Diamond", color: "#4fc3f7", multiplier: 4, qteCircles: 6, qteTime: 5 },
    legend: { label: "Legendary", color: "#ff6b6b", multiplier: 5, qteCircles: 7, qteTime: 4.5 }
  },
  fish: [
    { id: "minnow", name: "Minnow", emoji: "🐟", rarity: "bronze", spawnWeight: 400, minKg: 0.05, maxKg: 0.2 },
    { id: "bass", name: "Bass", emoji: "🐠", rarity: "silver", spawnWeight: 250, minKg: 0.5, maxKg: 4 },
    { id: "swordfish", name: "Swordfish", emoji: "🐡", rarity: "gold", spawnWeight: 60, minKg: 30, maxKg: 150 },
    { id: "marlin", name: "Marlin", emoji: "🦈", rarity: "diamond", spawnWeight: 38, minKg: 60, maxKg: 300 },
    { id: "kraken", name: "Kraken", emoji: "🐙", rarity: "legend", spawnWeight: 12, minKg: 500, maxKg: 5000 }
  ]
};

/* ---------------- tiny helpers ---------------- */

const readJson = (req) =>
  new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 500000) req.destroy(); });
    req.on("end", () => {
      try { resolve(JSON.parse(body || "{}")); } catch (e) { resolve({}); }
    });
    req.on("error", () => resolve({}));
  });

const send = (res, status, obj) => {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  });
  res.end(payload);
};

const lbFile = (channelId) => path.join(DATA_DIR, "leaderboard_" + String(channelId).replace(/[^a-zA-Z0-9_-]/g, "") + ".json");

function loadLeaderboard(channelId) {
  try { return JSON.parse(fs.readFileSync(lbFile(channelId), "utf8")); } catch (e) { return []; }
}
function saveLeaderboard(channelId, board) {
  fs.writeFileSync(lbFile(channelId), JSON.stringify(board, null, 2));
}

/* ---------------- JWT verification (HS256, extension secret) ---------------- */

function verifyJwt(token) {
  if (!SECRET_KEY || !token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  try {
    const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
    if (header.alg !== "HS256") return null;
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    // Compare raw signature bytes against the raw HMAC digest (digest() with
    // no encoding returns a Buffer). Comparing against a base64url string
    // re-encoded as ASCII would never match — and timingSafeEqual throws on
    // length mismatch, so every token failed here regardless of the secret.
    const expected = crypto.createHmac("sha256", SECRET_KEY).update(h + "." + p).digest();
    const sig = Buffer.from(s, "base64url");
    if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return null;
    if (payload.iss && payload.iss !== CLIENT_ID) return null;
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload; // opaque_user_id, channel_id, role, exp, ...
  } catch (e) {
    return null;
  }
}

/* ---------------- app access token + Helix calls ---------------- */

let tokenCache = null;

async function getAppToken() {
  if (tokenCache && tokenCache.expires_at > Date.now() + 60000) return tokenCache.access_token;
  if (!CLIENT_ID || !CLIENT_SECRET) return null;
  const res = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    })
  });
  const data = await res.json();
  if (!data.access_token) throw new Error("Could not get app access token: " + JSON.stringify(data));
  tokenCache = { access_token: data.access_token, expires_at: Date.now() + (data.expires_in || 3600) * 1000 };
  return data.access_token;
}

const helixHeaders = (token) => ({
  Authorization: "Bearer " + token,
  "Client-Id": CLIENT_ID,
  "Content-Type": "application/json"
});

async function verifyTransaction(transactionId, expectedBits) {
  const token = await getAppToken();
  const url = HELIX + "/extensions/transactions?extension_id=" + encodeURIComponent(CLIENT_ID) +
              "&id=" + encodeURIComponent(transactionId);
  const res = await fetch(url, { headers: helixHeaders(token) });
  if (!res.ok) throw new Error("Transaction lookup failed: " + res.status);
  const data = await res.json();
  const tx = data.data && data.data[0];
  if (!tx) throw new Error("Transaction not found");
  if (expectedBits && tx.product && tx.product.cost &&
      Number(tx.product.cost.amount) !== Number(expectedBits)) {
    throw new Error("Transaction amount mismatch");
  }
  return tx;
}

async function sendChatMessage(broadcasterId, message) {
  const token = await getAppToken();
  if (!token) throw new Error("No app token (set extension credentials)");
  const res = await fetch(HELIX + "/extensions/chat", {
    method: "POST",
    headers: helixHeaders(token),
    body: JSON.stringify({
      broadcaster_id: broadcasterId,
      extension_id: CLIENT_ID,
      extension_version: EXTENSION_VERSION,
      message: message
    })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error("Chat send failed (" + res.status + "): " + body.slice(0, 200));
  }
  return res.json();
}

async function broadcast(channelId, obj) {
  // Broadcasts fire from spawn-loop timers and request handlers. A Twitch API
  // failure here (bad/missing credentials, EXTENSION_VERSION mismatch, a
  // network hiccup) must never escape as an unhandled rejection and crash the
  // process — log it and skip this broadcast instead.
  try {
    const token = await getAppToken();
    if (!token) return;
    const res = await fetch(HELIX + "/extensions/pubsub", {
      method: "POST",
      headers: helixHeaders(token),
      body: JSON.stringify({
        target: [],
        broadcaster_id: channelId,
        is_broadcast: true,
        message: JSON.stringify(obj)
      })
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.error("Broadcast to " + channelId + " failed (" + res.status + "): " + body.slice(0, 200));
    }
  } catch (e) {
    console.error("Broadcast to " + channelId + " skipped after error: " + (e && e.message ? e.message : e));
  }
}

/* ---------------- per-channel state + synced spawn loop ---------------- */

const channels = new Map(); // channelId -> { lastSeen, config, activeSpawn, nextSpawnAt, loopTimer }

function getChannel(channelId) {
  let ch = channels.get(channelId);
  if (!ch) {
    ch = { lastSeen: 0, config: null, activeSpawn: null, nextSpawnAt: 0, loopTimer: null };
    channels.set(channelId, ch);
  }
  return ch;
}

function mergeConfig(base, over) {
  if (!over || typeof over !== "object") return base;
  const out = Array.isArray(base) ? base.slice() : Object.assign({}, base);
  for (const k of Object.keys(over)) {
    const bv = base[k], ov = over[k];
    if (ov && typeof ov === "object" && !Array.isArray(ov) &&
        bv && typeof bv === "object" && !Array.isArray(bv)) {
      out[k] = mergeConfig(bv, ov);
    } else if (ov !== undefined) out[k] = ov;
  }
  return out;
}

function getConfig(channelId) {
  const ch = getChannel(channelId);
  return mergeConfig(mergeConfig({}, FALLBACK_CONFIG), ch.config || {});
}

function randSpawnDelay(cfg) {
  const t = cfg.timer || {};
  const min = Math.max(3, Number(t.minSec) || 45);
  const max = Math.max(min, Number(t.maxSec) || 150);
  return (min + Math.random() * (max - min)) * 1000;
}

function pickFish(cfg) {
  const list = (cfg.fish && cfg.fish.length) ? cfg.fish : FALLBACK_CONFIG.fish;
  const total = list.reduce((s, f) => s + (Number(f.spawnWeight) > 0 ? Number(f.spawnWeight) : 1), 0);
  let r = Math.random() * total;
  for (const f of list) {
    r -= (Number(f.spawnWeight) > 0 ? Number(f.spawnWeight) : 1);
    if (r <= 0) return f;
  }
  return list[list.length - 1];
}

function startSpawn(channelId) {
  const ch = getChannel(channelId);
  const cfg = getConfig(channelId);
  const fish = pickFish(cfg);
  const minKg = Number(fish.minKg) || 0.1;
  const maxKg = Math.max(minKg, Number(fish.maxKg) || minKg + 1);
  const weightKg = minKg + Math.random() * (maxKg - minKg);
  const cl = Number((cfg.spawn || {}).catchLimit);
  const catchLimit = Number.isFinite(cl) ? Math.max(-1, Math.floor(cl)) : -1;
  const windowSec = Math.max(5, Number((cfg.spawn || {}).catchWindowSec) || 20);
  const spawn = {
    spawnId: Date.now() + "_" + Math.random().toString(36).slice(2, 7),
    fish: {
      id: fish.id || fish.name, name: fish.name, emoji: fish.emoji || "🐟",
      rarity: fish.rarity || "bronze"
    },
    weightKg: weightKg,
    spawnAt: Date.now(),
    windowEnd: Date.now() + windowSec * 1000,
    catchLimit: catchLimit,
    remaining: catchLimit,           // -1 for unlimited, else decrements
    raffle: catchLimit > 0,  // limited fish are always decided by raffle
    claims: [],                      // { uid, username, at, qteMs }
    claimed: new Set(),
    state: "active"
  };
  ch.activeSpawn = spawn;
  console.log("[spawn] " + channelId + " -> " + (fish.name || "?") + " " + weightKg.toFixed(1) + "kg limit=" + catchLimit);
  broadcast(channelId, { type: "spawn", spawn: publicSpawn(spawn) });
}

function publicSpawn(spawn) {
  return {
    spawnId: spawn.spawnId,
    fish: spawn.fish,
    weightKg: spawn.weightKg,
    spawnAt: spawn.spawnAt,
    windowEnd: spawn.windowEnd,
    catchLimit: spawn.catchLimit,
    remaining: spawn.remaining,
    raffle: spawn.raffle
  };
}

function weightedDraw(entrants, count) {
  // entrants is sorted fastest-first. The fastest entrant holds n tickets,
  // the slowest holds 1, so finishing faster strictly raises your odds.
  const n = entrants.length;
  const tickets = entrants.map((e, i) => ({ e: e, w: n - i }));
  const winners = [];
  while (winners.length < count && tickets.length) {
    let total = 0;
    for (const t of tickets) total += t.w;
    let r = Math.random() * total;
    for (let i = 0; i < tickets.length; i++) {
      r -= tickets[i].w;
      if (r <= 0) {
        winners.push(tickets[i].e);
        tickets.splice(i, 1);
        break;
      }
    }
  }
  return winners;
}

function resolveSpawn(channelId, reason) {
  const ch = getChannel(channelId);
  const spawn = ch.activeSpawn;
  if (!spawn || spawn.state !== "active") return;
  spawn.state = "resolving";

  if (spawn.catchLimit !== -1 && spawn.claims.length) {
    // Limited fish: raffle-only. Everyone who finished the QTE is entered;
    // the weighted draw favors the fastest finishers.
    const entrants = spawn.claims.slice().sort((a, b) => a.at - b.at);
    const winners = weightedDraw(entrants, spawn.catchLimit);
    console.log("[raffle] " + channelId + " entrants=" + entrants.length + " winners=" + winners.length + " (weighted by speed)");
    // Always broadcast the result so every entrant learns whether they won.
    broadcast(channelId, {
      type: "raffle_result",
      spawnId: spawn.spawnId,
      winners: winners.map(w => ({ username: w.username, opaqueUserId: w.uid }))
    });
  }

  broadcast(channelId, { type: "spawn_end", spawnId: spawn.spawnId });
  ch.activeSpawn = null;
  ch.nextSpawnAt = Date.now() + randSpawnDelay(getConfig(channelId));
  console.log("[spawn] " + channelId + " ended (" + reason + ") next in " + Math.round((ch.nextSpawnAt - Date.now()) / 1000) + "s");
}

function tick(channelId) {
  const ch = getChannel(channelId);
  if (!ch) return;
  if (Date.now() - ch.lastSeen > LIVENESS_MS) {
    // no viewers for a while — stop the loop
    if (ch.loopTimer) { clearInterval(ch.loopTimer); ch.loopTimer = null; }
    ch.activeSpawn = null;
    return;
  }
  const now = Date.now();
  if (ch.activeSpawn && ch.activeSpawn.state === "active") {
    if (now >= ch.activeSpawn.windowEnd) resolveSpawn(channelId, "timeout");
    return;
  }
  if (!ch.activeSpawn && (!ch.nextSpawnAt || now >= ch.nextSpawnAt)) {
    startSpawn(channelId);
  }
}

function ensureLoop(channelId) {
  const ch = getChannel(channelId);
  if (!ch.loopTimer) {
    // A bug or Twitch-side failure inside the tick must log and continue,
    // never take the process (and every other channel) down.
    ch.loopTimer = setInterval(() => {
      try {
        tick(channelId);
      } catch (e) {
        console.error("Spawn loop error for " + channelId + ": " + (e && e.message ? e.message : e));
      }
    }, 500);
  }
}

/* ---------------- request handling ---------------- */

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "OPTIONS") { send(res, 204, {}); return; }

  if (url.pathname === "/healthz" && req.method === "GET") { send(res, 200, { ok: true }); return; }

  // GET leaderboard
  if (url.pathname === "/api/leaderboard" && req.method === "GET") {
    const channelId = url.searchParams.get("channel_id") || "";
    if (!channelId) { send(res, 400, { error: "channel_id is required" }); return; }
    send(res, 200, { leaderboard: loadLeaderboard(channelId) });
    return;
  }

  // POST /api/hello — viewers announce themselves, share config, get current spawn
  if (url.pathname === "/api/hello" && req.method === "POST") {
    const body = await readJson(req);
    const { jwt, channelId } = body;
    if (!channelId) { send(res, 400, { error: "channelId is required" }); return; }

    let payload = null;
    if (INSECURE) {
      payload = { opaque_user_id: body.opaqueUserId || "insecure-user", channel_id: channelId, role: "viewer" };
    } else {
      payload = verifyJwt(jwt);
      if (!payload) { send(res, 401, { error: "Invalid JWT" }); return; }
      if (String(payload.channel_id) !== String(channelId)) { send(res, 403, { error: "Channel mismatch" }); return; }
    }

    const ch = getChannel(channelId);
    ch.lastSeen = Date.now();
    if (body.config && typeof body.config === "object") {
      ch.config = mergeConfig(ch.config || {}, body.config);
    }
    ensureLoop(channelId);
    send(res, 200, { ok: true, spawn: ch.activeSpawn ? publicSpawn(ch.activeSpawn) : null });
    return;
  }

  // POST /api/catch — a viewer finished the QTE; claim the fish
  if (url.pathname === "/api/catch" && req.method === "POST") {
    const body = await readJson(req);
    const { jwt, channelId, spawnId, qteMs } = body;
    if (!channelId || !spawnId) { send(res, 400, { error: "channelId and spawnId are required" }); return; }

    let uid = null, username = null;
    if (INSECURE) {
      uid = String(body.opaqueUserId || "insecure-user");
      username = String(body.username || "viewer").slice(0, 25);
    } else {
      const payload = verifyJwt(jwt);
      if (!payload) { send(res, 401, { error: "Invalid JWT" }); return; }
      if (String(payload.channel_id) !== String(channelId)) { send(res, 403, { error: "Channel mismatch" }); return; }
      uid = payload.opaque_user_id;
      username = null; // display names arrive via bits transactions; use opaque short id
    }

    const ch = getChannel(channelId);
    const spawn = ch.activeSpawn;
    if (!spawn || spawn.state !== "active" || spawn.spawnId !== spawnId) {
      send(res, 200, { status: "no_spawn" });
      return;
    }
    if (Date.now() > spawn.windowEnd) {
      resolveSpawn(channelId, "timeout");
      send(res, 200, { status: "too_late" });
      return;
    }
    if (spawn.claimed.has(uid)) {
      send(res, 200, { status: "already" });
      return;
    }
    spawn.claims.push({ uid: uid, username: username || uid.slice(0, 8), at: Date.now(), qteMs: Math.max(0, Number(qteMs) || 0) });
    spawn.claimed.add(uid);

    if (spawn.catchLimit === -1) {
      send(res, 200, { status: "caught", remaining: -1 });
      return;
    }

    // Limited fish: raffle-only. Hold the claim; winners are drawn when the
    // fish leaves (weighted by how fast each entrant finished).
    broadcast(channelId, { type: "attempt_count", spawnId: spawnId, attempts: spawn.claims.length });
    send(res, 200, { status: "entered", attempts: spawn.claims.length });
    return;
  }

  // POST /api/share — share: chat + leaderboard + broadcast. Paid shares are
  // bits-verified; free shares (fish.costBits === 0) skip the transaction.
  if (url.pathname === "/api/share" && req.method === "POST") {
    const body = await readJson(req);
    const { jwt, channelId, transactionId, fish } = body;
    if (!channelId || !fish) { send(res, 400, { error: "channelId and fish are required" }); return; }
    const costBits = Math.max(0, Number(fish.costBits) || 0);
    const freeShare = costBits === 0;

    let username = null;
    if (INSECURE) {
      username = String(fish.username || "viewer").slice(0, 25);
    } else {
      const payload = verifyJwt(jwt);
      if (!payload) { send(res, 401, { error: "Invalid JWT" }); return; }
      if (String(payload.channel_id) !== String(channelId)) { send(res, 403, { error: "Channel mismatch" }); return; }
      if (freeShare) {
        // Free share (0 bits): no purchase happened, so no transaction to verify.
        username = String(fish.username || "viewer").slice(0, 25);
      } else {
        if (!transactionId) { send(res, 400, { error: "transactionId is required" }); return; }
        try {
          const tx = await verifyTransaction(transactionId, costBits);
          username = String(fish.username || tx.displayName || "viewer").slice(0, 25);
        } catch (e) {
          send(res, 400, { error: "Transaction verification failed: " + e.message });
          return;
        }
      }
    }

    const rarity = String(fish.rarity || "bronze").slice(0, 20);
    const weightKg = Math.max(0, Number(fish.weightKg) || 0);
    const score = Math.max(0, Number(fish.score) || 0);
    const fishName = String(fish.fishName || "Fish").slice(0, 40);
    const entry = { username, fishName, rarity, weightKg, score, costBits, ts: Date.now() };

    const board = loadLeaderboard(channelId);
    board.push(entry);
    board.sort((a, b) => b.score - a.score || b.costBits - a.costBits);
    const maxEntries = Math.min(100, Math.max(1, Number(body.maxEntries) || 20));
    const trimmed = board.slice(0, maxEntries);
    saveLeaderboard(channelId, trimmed);

    let chatResult = null;
    const chatMessage = costBits === 0
      ? "@" + username + " caught a " + rarityLabel(rarity) + " " + fishName + " (" + fmtKg(weightKg) + ")! 🌊"
      : "@" + username + " caught a " + rarityLabel(rarity) + " " + fishName + " (" + fmtKg(weightKg) +
        ") worth " + costBits.toLocaleString("en-US") + " bits! 🌊";
    try {
      chatResult = await sendChatMessage(channelId, chatMessage);
    } catch (e) {
      console.error("chat:", e.message);
    }
    broadcast(channelId, { type: "leaderboard", leaderboard: trimmed }).catch((e) => console.error("pubsub:", e.message));

    send(res, 200, { ok: true, leaderboard: trimmed, chat: chatResult });
    return;
  }

  // POST /api/leaderboard/reset — broadcaster only
  if (url.pathname === "/api/leaderboard/reset" && req.method === "POST") {
    const body = await readJson(req);
    const { jwt, channelId } = body;
    let payload = null;
    if (INSECURE) {
      payload = { channel_id: channelId, role: "broadcaster" };
    } else {
      payload = verifyJwt(jwt);
      if (!payload) { send(res, 401, { error: "Invalid JWT" }); return; }
    }
    if (payload.role !== "broadcaster") { send(res, 403, { error: "Broadcaster only" }); return; }
    if (String(payload.channel_id) !== String(channelId)) { send(res, 403, { error: "Channel mismatch" }); return; }
    saveLeaderboard(channelId, []);
    broadcast(channelId, { type: "leaderboard", leaderboard: [] }).catch((e) => console.error("pubsub:", e.message));
    send(res, 200, { ok: true, leaderboard: [] });
    return;
  }

  send(res, 404, { error: "Not found" });
}

/* ---------------- display helpers ---------------- */

const RARITY_LABELS = { bronze: "Bronze", silver: "Silver", gold: "Gold", diamond: "Diamond", legend: "Legendary" };
function rarityLabel(key) { return RARITY_LABELS[key] || key; }
function fmtKg(kg) {
  if (kg < 1) return Math.round(kg * 1000) + " g";
  return kg.toLocaleString("en-US", { maximumFractionDigits: 1 }) + " kg";
}

/* ---------------- server ---------------- */

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error(e);
    send(res, 500, { error: "Internal error" });
  });
});

server.listen(PORT, () => {
  console.log("Aquarium Game EBS listening on http://localhost:" + PORT);
  console.log("  client id:      " + (CLIENT_ID || "(unset)"));
  console.log("  extension ver:  " + EXTENSION_VERSION);
  console.log("  data dir:       " + DATA_DIR);
  if (INSECURE) console.log("  ⚠ ALLOW_INSECURE mode — no JWT verification / Twitch calls");
});

// Last-resort guards: an async rejection (e.g. a Twitch API call made outside
// the guarded paths above) must log and let the service keep running instead
// of killing Node mid-spawn — which previously made viewers report "EBS
// unreachable" while Render restarted the process.
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection (keeping service alive):", reason);
});
process.on("uncaughtException", (e) => {
  console.error("Uncaught exception (keeping service alive):", e);
});