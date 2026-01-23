import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import { request } from "undici";

/**
 * ⚠️ Tijdelijk: nodig als FileMaker self-signed / verlopen cert heeft
 * (zelfde als je werkende proxy)
 */
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const app = express();

/* ---------- MIDDLEWARE ---------- */
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "5mb" }));
app.use(morgan("combined"));
app.use(
  cors({
    origin: process.env.ALLOW_ORIGIN
      ? process.env.ALLOW_ORIGIN.split(",")
      : true
  })
);

/* ---------- ENV ---------- */
const {
  PORT = 3000,
  API_SECRET,
  FM_BASE,
  FM_HOST,
  FM_DB,
  FM_LAYOUT,
  FM_USER,
  FM_PASS
} = process.env;

/* ---------- SANITY CHECKS (fail fast) ---------- */
const FM_ENDPOINT = FM_BASE || FM_HOST;

if (!API_SECRET) console.warn("⚠️ API_SECRET is not set");
if (!FM_ENDPOINT) console.warn("⚠️ FM_BASE / FM_HOST is not set");
if (!FM_DB) console.warn("⚠️ FM_DB is not set");
if (!FM_USER || !FM_PASS) console.warn("⚠️ FM credentials missing");
if (!FM_LAYOUT) console.warn("⚠️ FM_LAYOUT is not set");

/* ---------- AUTH ---------- */
function auth(req, res, next) {
  const key = req.header("x-api-key");
  if (!API_SECRET || key !== API_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

/* ---------- FILEMAKER LOGIN ---------- */
async function fmLogin() {
  if (!FM_ENDPOINT) throw new Error("FM endpoint not configured");
  if (!FM_DB) throw new Error("FM_DB not configured");
  if (!FM_USER || !FM_PASS) throw new Error("FM credentials missing");

  const url =
    `${FM_ENDPOINT}/fmi/data/vLatest/databases/` +
    `${encodeURIComponent(FM_DB)}/sessions`;

  const { statusCode, body } = await request(url, {
    method: "POST",
    headers: {
      Authorization:
        "Basic " + Buffer.from(`${FM_USER}:${FM_PASS}`).toString("base64"),
      "Content-Type": "application/json"
    },
    body: "{}"
  });

  const json = await body.json();

  if (statusCode !== 200 || !json?.response?.token) {
    throw new Error(
      `FM login failed (${statusCode}): ${JSON.stringify(json)}`
    );
  }

  return json.response.token;
}

/* ---------- ROUTES ---------- */

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/**
 * PREVIEW endpoint
 * - maakt GEEN records
 * - roept alleen FileMaker script aan
 */
app.post("/fm/servicebon/preview", auth, async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "body must be JSON object" });
    }

    if (!FM_LAYOUT) {
      throw new Error("FM_LAYOUT not configured");
    }

    const payloadString = JSON.stringify(req.body);
    const token = await fmLogin();

    const url =
      `${FM_ENDPOINT}/fmi/data/vLatest/databases/` +
      `${encodeURIComponent(FM_DB)}/layouts/` +
      `${encodeURIComponent(FM_LAYOUT)}/records`;

    const { statusCode, body } = await request(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        fieldData: {}, // ❗ bewust leeg (preview only)
        script: "API_Servicebon_PREVIEW",
        "script.param": payloadString
      })
    });

    const json = await body.json();

    return res.status(statusCode).json(json);
  } catch (err) {
    console.error("PREVIEW ERROR:", err);
    return res.status(500).json({
      error: err?.message || String(err)
    });
  }
});

/* ---------- START ---------- */
app.listen(PORT, () => {
  console.log(`FM preview proxy listening on port ${PORT}`);
});
