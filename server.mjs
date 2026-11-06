import http from "node:http";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_HOSTS = (process.env.PUBLIC_HOSTS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const IA = "https://archive.org";
const MAX_RESULTS = 12;
const MAX_QUERY = 160;

const manifest = {
  id: "dev.alijati.internetarchive.flac",
  name: "Internet Archive FLAC",
  version: "1.0.0",
  resources: ["search", "stream"],
  bitchordAuth: true,
  allowDownloads: 1,
  settings: [{
    key: "quality",
    type: "select",
    label: "Audio quality",
    default: "lossless",
    options: [
      { value: "lossless", label: "Lossless FLAC" },
      { value: "hires", label: "Hi-Res FLAC (verified only)" }
    ]
  }]
};

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers
  });
  res.end(JSON.stringify(body));
};

const b64url = (s) => Buffer.from(s, "base64url");
const decodePart = (s) => JSON.parse(b64url(s).toString("utf8"));

let jwksCache = { keys: null, expiresAt: 0, fetchedAt: 0 };

async function getJwks(force = false) {
  const now = Date.now();
  if (!force && jwksCache.keys && now < jwksCache.expiresAt) return jwksCache.keys;
  if (!force && now - jwksCache.fetchedAt < 5 * 60_000 && !jwksCache.keys) {
    throw new Error("BitChord public keys are not available yet");
  }
  jwksCache.fetchedAt = now;
  const response = await fetch("https://bitchord-auth.kushagrasingh.in/.well-known/jwks.json", {
    headers: { "accept": "application/json" },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error(`JWKS HTTP ${response.status}`);
  const data = await response.json();
  if (!Array.isArray(data.keys)) throw new Error("Invalid JWKS");
  jwksCache = { keys: data.keys, expiresAt: now + 60 * 60_000, fetchedAt: now };
  return data.keys;
}

function authFailure(res, code, message, status = 401) {
  return json(res, status, { error: "bitchord_auth", code, message }, {
    "www-authenticate": `BitChord realm="bitchord-addons", error="${code}", error_description="${message}"`
  });
}

async function verifyBitChord(req, res) {
  const token = req.headers["x-bitchord-token"];
  const proof = req.headers["x-bitchord-proof"];
  if (!token || !proof) {
    authFailure(res, "missing", "BitChord credentials are required");
    return false;
  }
  if (!PUBLIC_HOSTS.length) {
    authFailure(res, "unavailable", "Set PUBLIC_HOSTS to the public addon hostname", 503);
    return false;
  }

  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) {
      authFailure(res, "invalid_token", "Malformed token");
      return false;
    }
    const header = decodePart(parts[0]);
    const claims = decodePart(parts[1]);
    if (header.alg !== "EdDSA" || !header.kid) {
      authFailure(res, "invalid_token", "Unsupported token algorithm");
      return false;
    }

    let keys = await getJwks();
    let jwk = keys.find(k => k.kid === header.kid);
    if (!jwk) {
      keys = await getJwks(true);
      jwk = keys.find(k => k.kid === header.kid);
    }
    if (!jwk) {
      authFailure(res, "invalid_token", "Unknown signing key");
      return false;
    }

    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    const tokenOK = verifySignature(null, signingInput, publicKey, b64url(parts[2]));
    if (!tokenOK) {
      authFailure(res, "invalid_token", "Token signature is invalid");
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== "https://bitchord-auth.kushagrasingh.in" ||
        !aud.includes("bitchord-addons") ||
        typeof claims.exp !== "number" || claims.exp < now - 60 ||
        typeof claims.iat !== "number" || claims.iat > now + 60 ||
        claims.cnf?.jwk?.crv !== "P-256" || claims.cnf?.jwk?.kty !== "EC") {
      authFailure(res, claims.exp < now - 60 ? "expired" : "invalid_token", "Token claims are invalid");
      return false;
    }

    const match = String(proof).match(/^v1\.(\d{10,16})\.([A-Za-z0-9_-]{86})$/);
    if (!match) {
      authFailure(res, "invalid_proof", "Malformed device proof");
      return false;
    }
    const timestamp = Number(match[1]);
    if (Math.abs(Date.now() - timestamp) > 120_000) {
      authFailure(res, "stale_proof", "Device proof timestamp is stale");
      return false;
    }

    const tokenHash = createHash("sha256").update(token).digest("base64url");
    const signatureMessagePrefix = `bitchord-addon-proof/v1\n`;
    const signature = b64url(match[2]);
    const deviceKey = createPublicKey({ key: claims.cnf.jwk, format: "jwk" });

    let valid = false;
    for (const host of PUBLIC_HOSTS) {
      const message = Buffer.from(`${signatureMessagePrefix}${host}\n${match[1]}\n${tokenHash}`, "utf8");
      // BitChord sends a 64-byte IEEE-P1363 ECDSA signature (r || s).
      if (verifySignature("sha256", message, { key: deviceKey, dsaEncoding: "ieee-p1363" }, signature)) {
        valid = true;
        break;
      }
    }
    if (!valid) {
      authFailure(res, "invalid_proof", "Device proof did not match this addon hostname");
      return false;
    }
    return true;
  } catch (error) {
    console.error("BitChord auth error:", error?.message || error);
    authFailure(res, "unavailable", "Could not verify BitChord credentials", 503);
    return false;
  }
}

function isOpenLicense(value) {
  if (!value) return false;
  const s = String(value).toLowerCase();
  return s.includes("creativecommons.org/licenses/") ||
         s.includes("creativecommons.org/publicdomain/") ||
         s.includes("creativecommons.org/publicdomain/mark");
}

function cleanText(value, fallback = "") {
  if (Array.isArray(value)) value = value[0];
  return typeof value === "string" ? value : fallback;
}

async function searchInternetArchive(query, quality) {
  const q = query.trim().slice(0, MAX_QUERY);
  if (!q) return [];
  const params = new URLSearchParams({
    q: `mediatype:audio AND (${q.replace(/[+\-!(){}\[\]^"~*?:\\/]/g, " ").trim()})`,
    fl: "identifier,title,creator",
    rows: "30",
    page: "1",
    output: "json"
  });
  const response = await fetch(`${IA}/advancedsearch.php?${params}`, {
    headers: { "user-agent": "BitChordInternetArchiveAddon/1.0 (metadata lookup)" },
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error(`Internet Archive search HTTP ${response.status}`);
  const data = await response.json();
  const docs = data.response?.docs || [];
  const found = [];

  for (const doc of docs.slice(0, 18)) {
    try {
      const metaRes = await fetch(`${IA}/metadata/${encodeURIComponent(doc.identifier)}`, {
        headers: { "user-agent": "BitChordInternetArchiveAddon/1.0 (metadata lookup)" },
        signal: AbortSignal.timeout(10000)
      });
      if (!metaRes.ok) continue;
      const item = await metaRes.json();
      const license = cleanText(item.metadata?.licenseurl);
      if (!isOpenLicense(license)) continue;

      const flacs = (item.files || []).filter(f =>
        typeof f.name === "string" &&
        f.name.toLowerCase().endsWith(".flac") &&
        !f.name.includes("__ia_thumb")
      );
      for (const file of flacs.slice(0, 3)) {
        const isHiRes = Number(file.bitdepth || file.bit_depth || 0) >= 24 &&
                        Number(file.samplerate || file.sample_rate || 0) >= 88200;
        if (quality === "hires" && !isHiRes) continue;
        const id = Buffer.from(JSON.stringify({
          identifier: doc.identifier,
          filename: file.name,
          license
        })).toString("base64url");
        found.push({
          id,
          title: cleanText(item.metadata?.title, doc.title || doc.identifier),
          artist: cleanText(item.metadata?.creator, cleanText(doc.creator, "Internet Archive contributor")),
          album: cleanText(item.metadata?.collection, "Internet Archive"),
          duration: Number(file.length) || undefined,
          artworkURL: `${IA}/services/img/${encodeURIComponent(doc.identifier)}`,
          format: "flac",
          audioQuality: isHiRes ? "HI-RES LOSSLESS" : "LOSSLESS"
        });
        if (found.length >= MAX_RESULTS) return found;
      }
    } catch (e) {
      console.warn("Skipping IA item:", doc.identifier, e?.message || e);
    }
  }
  return found;
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (req.method !== "GET") return json(res, 405, { error: "method_not_allowed" });

  if (url.pathname === "/health") {
    return json(res, 200, { ok: true, service: "bitchord-internetarchive-flac" });
  }
  if (url.pathname === "/manifest.json") return json(res, 200, manifest);

  if (!await verifyBitChord(req, res)) return;

  if (url.pathname === "/search") {
    const q = url.searchParams.get("q") || "";
    const quality = (url.searchParams.get("quality") || "lossless").toLowerCase();
    try {
      const tracks = await searchInternetArchive(q, quality);
      return json(res, 200, { tracks });
    } catch (e) {
      console.error("Search failed:", e?.message || e);
      return json(res, 502, { tracks: [], error: "Internet Archive search is temporarily unavailable" });
    }
  }

  if (url.pathname.startsWith("/stream/")) {
    try {
      const id = decodeURIComponent(url.pathname.slice("/stream/".length));
      const decoded = JSON.parse(Buffer.from(id, "base64url").toString("utf8"));
      if (!decoded.identifier || !decoded.filename || !isOpenLicense(decoded.license)) {
        return json(res, 404, { error: "Track not found or license not verified" });
      }
      const metaRes = await fetch(`${IA}/metadata/${encodeURIComponent(decoded.identifier)}`, {
        signal: AbortSignal.timeout(10000)
      });
      if (!metaRes.ok) return json(res, 404, { error: "Item unavailable" });
      const item = await metaRes.json();
      const file = (item.files || []).find(f => f.name === decoded.filename);
      if (!file || !decoded.filename.toLowerCase().endsWith(".flac")) {
        return json(res, 404, { error: "FLAC file unavailable" });
      }
      const currentLicense = cleanText(item.metadata?.licenseurl);
      if (!isOpenLicense(currentLicense)) return json(res, 404, { error: "Open license could not be confirmed" });

      const fileURL = `${IA}/download/${encodeURIComponent(decoded.identifier)}/${decoded.filename.split("/").map(encodeURIComponent).join("/")}`;
      const isHiRes = Number(file.bitdepth || file.bit_depth || 0) >= 24 &&
                      Number(file.samplerate || file.sample_rate || 0) >= 88200;
      if ((url.searchParams.get("quality") || "").toLowerCase() === "hires" && !isHiRes) {
        return json(res, 404, { error: "Verified Hi-Res FLAC is not available for this recording" });
      }
      const body = {
        url: fileURL,
        format: "flac",
        codec: "flac",
        container: "flac",
        manifest: "none",
        encrypted: false,
        quality: isHiRes ? "Hi-Res FLAC (verified metadata)" : "Lossless FLAC (bit depth/sample rate not verified)"
      };
      if (isHiRes) {
        body.bitDepth = Number(file.bitdepth || file.bit_depth);
        body.sampleRate = Number(file.samplerate || file.sample_rate);
      }
      if (Number(file.size) > 0 && Number(file.length) > 0) {
        body.bitrate = Math.round((Number(file.size) * 8) / Number(file.length));
      }
      return json(res, 200, body);
    } catch {
      return json(res, 404, { error: "Invalid or unavailable track" });
    }
  }
  return json(res, 404, { error: "not_found" });
}

http.createServer((req, res) => {
  handle(req, res).catch(err => {
    console.error(err);
    if (!res.headersSent) json(res, 500, { error: "internal_error" });
    else res.end();
  });
}).listen(PORT, "0.0.0.0", () => {
  console.log(`BitChord Internet Archive FLAC addon listening on :${PORT}`);
  if (!PUBLIC_HOSTS.length) console.warn("Set PUBLIC_HOSTS before using in BitChord.");
});
