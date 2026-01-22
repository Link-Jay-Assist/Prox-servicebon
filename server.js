import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import { request } from "undici";

const app = express();
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(morgan("combined"));
app.use(cors({ origin: process.env.ALLOW_ORIGIN?.split(",") ?? "*" }));

const {
  PORT = 3000,
  API_SECRET,
  FM_BASE,
  FM_DB,
  FM_LAYOUT,
  FM_USER,
  FM_PASS
} = process.env;

function auth(req, res, next) {
  const key = req.header("x-api-key");
  if (!API_SECRET || key !== API_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

async function fmLogin() {
  const url = `${FM_BASE}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}/sessions`;
  const { statusCode, body } = await request(url, {
    method: "POST",
    headers: {
      Authorization:
        "Basic " + Buffer.from(`${FM_USER}:${FM_PASS}`).toString("base64")
    }
  });

  const json = await body.json();
  if (statusCode >= 300) {
    throw new Error(`FM login failed: ${statusCode} ${JSON.stringify(json)}`);
  }
  return json.response.token;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/fm/servicebon/preview", auth, async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "body must be JSON object" });
    }
    const payloadString = JSON.stringify(req.body);

    const token = await fmLogin();

    const url =
      `${FM_BASE}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}` +
      `/layouts/${encodeURIComponent(FM_LAYOUT)}/records`;

    const { statusCode, body } = await request(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        fieldData: {},
        script: "API_Servicebon_PREVIEW",
        "script.param": payloadString
      })
    });

    const json = await body.json();
    return res.status(statusCode).json(json);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message ?? e) });
  }
});

app.listen(PORT, () => console.log(`proxy listening on ${PORT}`));
