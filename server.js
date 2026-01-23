// server.js (ESM)
// Doel: simpele proxy naar FileMaker Data API, met endpoint:
// POST /fm/servicebon/preview  (stuurt body door als script param)
// GET  /health

import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import { request as ureq } from "undici";

// Optioneel: accepteer self-signed / verlopen certs (alleen als je dit echt nodig hebt)
if (String(process.env.FM_INSECURE_TLS || "").toLowerCase() === "true") {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const {
  PORT = 3000,

  // auth voor jouw proxy
  API_SECRET,

  // FileMaker config (ondersteunt zowel FM_BASE als FM_HOST)
  FM_BASE,
  FM_HOST,
  FM_DB,
  FM_LAYOUT,
  FM_USER,
  FM_PASS,

  // token cache TTL in minuten (default 12)
  FM_TOKEN_TTL_MIN = "12",

  // CORS
  ALLOW_ORIGIN,
} = process.env;

const FM_ORIGIN = (FM_BASE || FM_HOST || "").replace(/\/+$/, ""); // zonder trailing slash

// ---- basic startup validation (geeft duidelijke errors in logs) ----
const missing = [];
if (!API_SECRET) missing.push("API_SECRET");
if (!FM_ORIGIN) missing.push("FM_BASE (of FM_HOST)");
if (!FM_DB) missing.push("FM_DB");
if (!FM_LAYOUT) missing.push("FM_LAYOUT");
if (!FM_USER) missing.push("FM_USER");
if (!FM_PASS) missing.push("FM_PASS");

if (missing.length) {
  console.error(
    `[BOOT] Missing env vars: ${missing.join(
      ", "
    )}\nTip: in Elestio moet je env vars in de service/pipeline zetten; .env in GitHub wordt vaak overschreven.`
  );
  // niet hard-exiten als je liever health wil kunnen hitten; maar meestal is exit beter:
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(morgan("tiny"));

// ---- CORS ----
// ALLOW_ORIGIN kan zijn: "*" of "https://a.com,https://b.com"
let corsOrigin = true;
if (ALLOW_ORIGIN && ALLOW_ORIGIN.trim() !== "" && ALLOW_ORIGIN.trim() !== "*") {
  corsOrigin = ALLOW_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean);
}
app.use(cors({ origin: corsOrigin }));

// ---- auth helper (ondersteunt jouw verschillende manieren) ----
function okAuth(req) {
  const secret = String(API_SECRET || "");
  if (!secret) return false;

  // 1) x-api-key: <secret>
  const xApiKey = (req.header("x-api-key") || "").trim();
  if (xApiKey && xApiKey === secret) return true;

  // 2) X-Webhook-Secret: <secret>
  const xWebhook = (req.header("X-Webhook-Secret") || "").trim();
  if (xWebhook && xWebhook === secret) return true;

  // 3) Authorization: Bearer <secret>
  const auth = (req.header("Authorization") || "").trim();
  if (auth.toLowerCase().startsWith("bearer ")) {
    const tok = auth.slice(7).trim();
    if (tok === secret) return true;
  }

  return false;
}

function requireAuth(req, res, next) {
  if (!okAuth(req)) return res.status(401).json({ error: "unauthorized" });
  next();
}

// ---- undici JSON helper ----
async function jsonFetch(url, opts = {}) {
  const r = await ureq(url, opts);
  const t = await r.body.text();
  let json;
  try {
    json = t ? JSON.parse(t) : null;
  } catch {
    json = { raw: t };
  }
  return { status: r.statusCode, json };
}

// ---- token caching ----
let cachedToken = null;
let tokenExpMs = 0;

async function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpMs) return cachedToken;

  const basic = Buffer.from(`${FM_USER}:${FM_PASS}`).toString("base64");

  const { status, json } = await jsonFetch(
    `${FM_ORIGIN}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}/sessions`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/json",
      },
      body: "{}",
      // undici timeout (ms)
      // (undici v5/6 gebruikt dispatcher timeouts; dit helpt iig tegen “hangs”)
      headersTimeout: 15000,
      bodyTimeout: 15000,
    }
  );

  if (status !== 200 || !json?.response?.token) {
    throw new Error(`FM login failed: ${status} ${JSON.stringify(json)}`);
  }

  cachedToken = json.response.token;
  tokenExpMs = now + Number(FM_TOKEN_TTL_MIN || 12) * 60 * 1000;
  return cachedToken;
}

// ---- routes ----
app.get("/health", (_req, res) => res.json({ ok: true }));

/**
 * POST /fm/servicebon/preview
 * Body: { ... }  (wordt 1-op-1 doorgegeven als script.param JSON string)
 *
 * FileMaker call:
 * POST /layouts/<FM_LAYOUT>/records
 * body: { fieldData: {}, script: "API_Servicebon_PREVIEW", "script.param": "<stringified body>" }
 */
app.post("/fm/servicebon/preview", requireAuth, async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
      return res.status(400).json({ error: "body must be a JSON object" });
    }

    const payloadString = JSON.stringify(req.body);

    // token
    let token = await getToken();

    const fmUrl =
      `${FM_ORIGIN}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}` +
      `/layouts/${encodeURIComponent(FM_LAYOUT)}/records`;

    const callFM = async (tok) =>
      jsonFetch(fmUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tok}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          fieldData: {},
          script: "API_Servicebon_PREVIEW",
          "script.param": payloadString,
        }),
        headersTimeout: 20000,
        bodyTimeout: 20000,
      });

    // 1e poging
    let r = await callFM(token);

    // als token verlopen is: retry 1x
    if (r.status === 401) {
      cachedToken = null;
      token = await getToken();
      r = await callFM(token);
    }

    return res.status(r.status).json(r.json);
  } catch (e) {
    // netjes foutlog (zonder secrets te dumpen)
    const msg = String(e?.message || e);
    console.error("[/fm/servicebon/preview] error:", msg);
    return res.status(500).json({ error: msg });
  }
});

// ---- start ----
app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`FM proxy listening on ${PORT}`);
  console.log(`FM origin: ${FM_ORIGIN}`);
});
