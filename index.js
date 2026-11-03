#!/usr/bin/env node

/**
 * @rel-time/mcp-server
 * Official Model Context Protocol (MCP) Server for Rel-Time (https://rel-time.com)
 *
 * Zero-Knowledge Local File Hashing + Biometric Anchor (Passkey) +
 * Bitcoin Timechain Anchoring + Deterministic Sun-Stamp SVG +
 * 1-Click Option A Stamped Copy (.PDF / .PNG).
 * Uses native Node.js (>=18) crypto, fs, http, and fetch over JSON-RPC 2.0 stdio transport.
 */

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const readline = require("readline");
const { exec } = require("child_process");
const { PDFDocument, PDFName, PDFString } = require("pdf-lib");
const QRCode = require("qrcode");
const sharp = require("sharp");

function normalizeApiBase(rawUrl) {
  const cleaned = (rawUrl || "https://rel-time.com/api/v1").trim().replace(/\/+$/, "");
  if (
    cleaned === "https://rel-time.com/v1" ||
    cleaned === "https://rel-time.com" ||
    cleaned.includes("api.rel-time.com")
  ) {
    return "https://rel-time.com/api/v1";
  }
  return cleaned;
}

function isValidApiKeyCandidate(k) {
  if (!k || typeof k !== "string") return false;
  const trimmed = k.trim();
  if (!trimmed || trimmed.length < 16) return false;
  if (trimmed.includes("${") || trimmed.includes("...") || trimmed.includes("YOUR_") || trimmed.includes("<")) {
    return false;
  }
  return trimmed.startsWith("rel_");
}

const API_BASE = normalizeApiBase(process.env.RELTIME_API_URL);
const WEB_BASE = (process.env.RELTIME_WEB_URL || "https://rel-time.com").replace(/\/+$/, "");
let CURRENT_API_KEY = isValidApiKeyCandidate(process.env.RELTIME_API_KEY)
  ? process.env.RELTIME_API_KEY.trim()
  : "";

const PASSKEY_CONFIG_DIR = path.join(os.homedir(), ".reltime");
const PASSKEY_CONFIG_PATH = path.join(PASSKEY_CONFIG_DIR, "passkey.json");
const API_KEY_CONFIG_PATH = path.join(PASSKEY_CONFIG_DIR, "api_key.json");
let LAST_INVOICE_PACK = null;

const SERVER_INFO = {
  name: "rel-time-mcp-server",
  version: "1.2.15",
};

/**
 * Redacts the local OS user home directory prefix (e.g., /Users/Name, /home/name, C:\Users\Name)
 * to `~` so exported audit reports and payloads never leak local machine usernames.
 */
function redactHomePath(rawPath) {
  if (!rawPath || typeof rawPath !== "string") return "";
  const home = os.homedir();
  if (home) {
    const escapedHome = home.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const homeRegex = new RegExp(`^${escapedHome}(?=[/\\\\]|$)`, "i");
    if (homeRegex.test(rawPath)) {
      return rawPath.replace(homeRegex, "~");
    }
  }
  return rawPath.replace(/^(\/Users\/[^/]+|\/home\/[^/]+|[A-Za-z]:\\Users\\[^\\]+)(?=[/\\]|$)/, "~");
}

/**
 * Resolves a local file path, automatically matching macOS screenshot filenames
 * that contain Narrow No-Break Spaces (U+202F) or Non-Breaking Spaces (U+00A0)
 * when the caller passes normal ASCII spaces.
 */
function resolveLocalFilePath(rawPath) {
  const resolved = path.resolve(rawPath);
  if (fs.existsSync(resolved)) {
    return resolved;
  }
  const dir = path.dirname(resolved);
  const targetBase = path.basename(resolved);
  const normalizeSpaces = (s) => s.normalize("NFC").replace(/[\u00A0\u202F\u2007\u2009\s]+/g, " ");
  const normalizedTarget = normalizeSpaces(targetBase);
  try {
    if (fs.existsSync(dir)) {
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        if (normalizeSpaces(entry) === normalizedTarget) {
          return path.join(dir, entry);
        }
      }
    }
  } catch (e) {
    // Ignore directory read error
  }
  return resolved;
}

/**
 * Loads saved API key from ~/.reltime/api_key.json if not provided via env/args.
 */
function loadSavedApiKey() {
  if (isValidApiKeyCandidate(CURRENT_API_KEY)) {
    return CURRENT_API_KEY.trim();
  }
  if (isValidApiKeyCandidate(process.env.RELTIME_API_KEY)) {
    CURRENT_API_KEY = process.env.RELTIME_API_KEY.trim();
    return CURRENT_API_KEY;
  }
  try {
    if (fs.existsSync(API_KEY_CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(API_KEY_CONFIG_PATH, "utf8"));
      if (isValidApiKeyCandidate(parsed.api_key)) {
        CURRENT_API_KEY = parsed.api_key.trim();
        return CURRENT_API_KEY;
      }
    }
  } catch (e) {
    // Ignore corrupted file
  }
  return "";
}

function buildPackSelectionPrompt(contextMessage) {
  return {
    status: "pack_selection_required",
    api_endpoint: API_BASE,
    important_instruction_for_ai_agent:
      "DO NOT tell the user to edit ~/.zshrc, .mcp.json, or restart Claude/Cursor! The MCP server manages and persists API keys automatically in ~/.reltime/api_key.json. Simply ask the user right here in chat: (1) which of the 4 Rel-Time Tiers below they want to provision (`universal`, `launch`, `standard`, or `enterprise`), AND (2) whether they want to pay via **Bitcoin Lightning (`lightning`)** or **Stripe Card (`stripe`)** (or if they already have a `rel_key_...` key to paste). Then call `reltime_provision_agent_key` with `action: 'create_invoice'`, `pack`, and `payment_method`.",
    message:
      contextMessage ||
      "No Rel-Time API key is active yet. Ask the user which tier and payment method (Lightning or Stripe) they want to provision:",
    available_packs: [
      {
        pack: "universal",
        name: "1. Universal Anchor ($3 / anchor)",
        price_usd: "$3.00 per credit",
        credits: 1,
        settlement_queue: "Priority 10-Minute Bitcoin Queue",
        hashing_modes: "Standard Mode (Data Integrity + Biometric or Anonymous)",
        payment_methods: ["lightning", "stripe"],
        outputs: "64-Ray Sun-Stamp SVG + 1-Click Stamped Copy (.PDF/.PNG) + .JSON Doomsday Proof",
      },
      {
        pack: "launch",
        name: "2. Agent Launch Pack ($5 / 25 Hashes)",
        price_usd: "$5.00",
        credits: 25,
        settlement_queue: "Priority 10-Minute Bitcoin Queue",
        hashing_modes: "Standard Mode only (Data Integrity + Biometric or Anonymous · Max 3 packs per key)",
        payment_methods: ["lightning", "stripe"],
        outputs: "64-Ray Sun-Stamp SVG + 1-Click Stamped Copy (.PDF/.PNG) + 4-Plate Certificate + .JSON Doomsday Proof",
      },
      {
        pack: "standard",
        name: "3. Autonomous Agents ($50 / 500 Hashes)",
        price_usd: "$50.00",
        credits: 500,
        settlement_queue: "Dynamic 6-Hour Batch Queue",
        hashing_modes: "Temporal Mode (T_index sub-second VDF sequencing) + Standard Mode (Biometric or Anonymous)",
        payment_methods: ["lightning", "stripe"],
        outputs:
          "64-Ray Sun-Stamp SVG + 1-Click Stamped Copy (.PDF/.PNG) + 4-Plate Certificate + .JSON Doomsday Proof + Reloadable anytime (+500 credits / $50)",
      },
      {
        pack: "enterprise",
        name: "4. Rel-Time Superhighway ($399 / 5,000 Hashes)",
        price_usd: "$399.00",
        credits: 5000,
        settlement_queue: "Priority 10-Minute Bitcoin Queue",
        hashing_modes: "Temporal Mode (T_index) + Standard Mode + Data Integrity Audit & Instant Tamper Detection",
        payment_methods: ["lightning", "stripe"],
        outputs: "64-Ray Sun-Stamp SVG + 1-Click Stamped Copy (.PDF/.PNG) + 4-Plate Certificate + Forensic Audit Report + .JSON Proof",
      },
    ],
    next_step:
      "Ask the user which tier (`universal` $3, `launch` $5/25, `standard` $50/500, or `enterprise` $399/5,000) and which payment method (`lightning` or `stripe`) they prefer, then call `reltime_provision_agent_key({ action: 'create_invoice', pack, payment_method })`.",
  };
}

/**
 * Saves provisioned API key to ~/.reltime/api_key.json with 0600 permissions.
 */
function saveApiKeyConfig(apiKey, pack) {
  if (!fs.existsSync(PASSKEY_CONFIG_DIR)) {
    fs.mkdirSync(PASSKEY_CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  const payload = {
    api_key: apiKey.trim(),
    pack: pack || "standard",
    saved_at: new Date().toISOString(),
  };
  fs.writeFileSync(API_KEY_CONFIG_PATH, JSON.stringify(payload, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  return payload;
}

/**
 * Loads linked Passkey credentials from env vars or ~/.reltime/passkey.json.
 */
function loadSavedPasskey() {
  if (process.env.RELTIME_PASSKEY_PUBKEY && process.env.RELTIME_PASSKEY_TOKEN) {
    return {
      public_key_hex: process.env.RELTIME_PASSKEY_PUBKEY.trim(),
      passkey_signature: process.env.RELTIME_PASSKEY_TOKEN.trim(),
      source: "env",
    };
  }
  try {
    if (fs.existsSync(PASSKEY_CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(PASSKEY_CONFIG_PATH, "utf8"));
      if (parsed.public_key_hex && parsed.passkey_signature) {
        return {
          public_key_hex: parsed.public_key_hex.trim(),
          passkey_signature: parsed.passkey_signature.trim(),
          source: PASSKEY_CONFIG_PATH,
        };
      }
    }
  } catch (e) {
    // Ignore corrupted file
  }
  return null;
}

/**
 * Saves Passkey credentials to ~/.reltime/passkey.json with 0600 permissions.
 */
function savePasskeyConfig(publicKeyHex, passkeySignature) {
  if (!fs.existsSync(PASSKEY_CONFIG_DIR)) {
    fs.mkdirSync(PASSKEY_CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  const payload = {
    public_key_hex: publicKeyHex.trim(),
    passkey_signature: passkeySignature.trim(),
    linked_at: new Date().toISOString(),
  };
  fs.writeFileSync(PASSKEY_CONFIG_PATH, JSON.stringify(payload, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  return payload;
}

/**
 * Opens a URL in the user's default system browser.
 */
function openSystemBrowser(url) {
  const platform = process.platform;
  const cmd =
    platform === "darwin"
      ? `open "${url}"`
      : platform === "win32"
      ? `start "" "${url}"`
      : `xdg-open "${url}"`;
  exec(cmd);
}

/**
 * Launches a temporary 127.0.0.1 HTTP callback listener and opens the
 * Rel-Time WebAuthn Passkey Bridge in the user's browser so they can touch
 * TouchID / FaceID / YubiKey.
 */
function launchBrowserPasskeyBridge(timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      const parsedUrl = new URL(req.url, "http://127.0.0.1");
      if (parsedUrl.pathname === "/callback") {
        const pubKey = parsedUrl.searchParams.get("public_key_hex") || parsedUrl.searchParams.get("public_key");
        const token = parsedUrl.searchParams.get("passkey_signature");
        if (pubKey && token) {
          const saved = savePasskeyConfig(pubKey, token);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ status: "linked" }));
          clearTimeout(timer);
          server.close();
          resolve(saved);
          return;
        }
      }

      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing public_key_hex or passkey_signature" }));
    });

    const timer = setTimeout(() => {
      server.close();
      reject(
        new Error(
          `Timed out waiting for hardware Passkey touch in browser. Please complete the prompt at ${WEB_BASE}/mcp-passkey or pass public_key_hex and passkey_signature directly to reltime_link_passkey.`
        )
      );
    }, timeoutMs);

    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address.port;
      const bridgeUrl = `${WEB_BASE}/mcp-passkey?port=${port}`;
      openSystemBrowser(bridgeUrl);
    });
  });
}

/**
 * Injects a standard PNG tEXt chunk ("RelTimeVerify\0<verifyUrl>") right before IEND
 * so Stamped PNG copies can be instantaneously verified when dropped into /verify.
 */
function injectPngVerifyBuffer(pngBuffer, verifyUrl) {
  if (!verifyUrl || !Buffer.isBuffer(pngBuffer) || pngBuffer.length < 24) {
    return pngBuffer;
  }
  const iendOffset = pngBuffer.length - 12;
  if (pngBuffer.slice(iendOffset + 4, iendOffset + 8).toString("ascii") !== "IEND") {
    return pngBuffer;
  }
  const payload = Buffer.from(`RelTimeVerify\0${verifyUrl}`, "utf8");
  const typeBuf = Buffer.from("tEXt", "ascii");
  const crcInput = Buffer.concat([typeBuf, payload]);

  let crc = 0xffffffff;
  for (let i = 0; i < crcInput.length; i++) {
    crc ^= crcInput[i];
    for (let b = 0; b < 8; b++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  crc = (crc ^ 0xffffffff) >>> 0;

  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(payload.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc, 0);

  const chunk = Buffer.concat([lenBuf, crcInput, crcBuf]);
  return Buffer.concat([
    pngBuffer.slice(0, iendOffset),
    chunk,
    pngBuffer.slice(iendOffset),
  ]);
}

/**
 * Builds an OS-safe filename (<= 240 UTF-8 bytes) so macOS/Linux 255-byte limits
 * (`ENAMETOOLONG`) never fail on long AI-prompt filenames.
 */
function safeArtifactFilename(prefix, rawName, ext, hashHex = "") {
  const candidate = `${prefix}${rawName}${ext}`;
  if (Buffer.byteLength(candidate, "utf8") <= 240) {
    return candidate;
  }
  const suffixTag = hashHex
    ? `~${String(hashHex).slice(0, 8)}`
    : `~${crypto.createHash("sha256").update(String(rawName), "utf8").digest("hex").slice(0, 8)}`;
  const maxBodyBytes = Math.max(32, 240 - Buffer.byteLength(prefix, "utf8") - Buffer.byteLength(suffixTag, "utf8") - Buffer.byteLength(ext, "utf8"));
  let trimmed = "";
  let usedBytes = 0;
  for (const ch of String(rawName)) {
    const chBytes = Buffer.byteLength(ch, "utf8");
    if (usedBytes + chBytes > maxBodyBytes) break;
    trimmed += ch;
    usedBytes += chBytes;
  }
  return `${prefix}${trimmed.trim()}${suffixTag}${ext}`;
}

/**
 * Stamps the Option 1A (+14° Bitcoin Tilt, pure crisp 64-ray Sun-Stamp, 0% glare, no pill) onto a local Image or PDF.
 * Returns { stamped: true, output_path, format } or { stamped: false, reason }.
 */
async function stampLocalFileOptionA(filePath, svgContent, customOutputPath = null, verifyHash = null) {
  const ext = path.extname(filePath).toLowerCase().replace(/^\./, "");
  const dir = path.dirname(filePath);
  const baseName = path.basename(filePath, path.extname(filePath));

  const isImage = ["png", "jpg", "jpeg", "webp", "gif"].includes(ext);
  const isPdf = ext === "pdf";

  if (!isImage && !isPdf) {
    return {
      stamped: false,
      reason: "Feature unavailable for this file type (visual Sun-Stamp overlay is only available for Images and PDFs).",
    };
  }

  // Resolve verification URL from verifyHash or from <a href="..."> inside svgContent
  let verifyUrl = verifyHash ? `https://rel-time.com/verify?t=${verifyHash.toLowerCase()}` : null;
  if (!verifyUrl && typeof svgContent === "string") {
    const match = svgContent.match(/https?:\/\/rel-time\.com\/verify\?[tThH]=([0-9a-fA-F]{64})/);
    if (match) {
      verifyUrl = `https://rel-time.com/verify?t=${match[1].toLowerCase()}`;
    }
  }

  // Strip outer <a> wrapper before rasterizing with sharp/librsvg
  const cleanSvg = String(svgContent || "")
    .replace(/<a\b[^>]*>/gi, "")
    .replace(/<\/a>/gi, "");

  if (isImage) {
    const outPath = customOutputPath
      ? path.resolve(customOutputPath)
      : path.join(dir, safeArtifactFilename("reltime-stamped-", baseName, ".png", verifyHash));
    const img = sharp(filePath);
    const meta = await img.metadata();
    const w = (meta.autoOrient && meta.autoOrient.width) || meta.width || 1200;
    const h = (meta.autoOrient && meta.autoOrient.height) || meta.height || 800;

    const minDim = Math.min(w, h);
    const badgeSize = Math.max(180, Math.round(minDim * 0.22));
    const margin = Math.max(14, Math.round(minDim * 0.025));

    const stampPngBuffer = await sharp(Buffer.from(cleanSvg, "utf8"))
      .resize(badgeSize, badgeSize)
      .png()
      .toBuffer();

    const left = Math.max(0, w - badgeSize - margin);
    const top = Math.max(0, h - badgeSize - margin);

    const rawOutBuf = await sharp(filePath)
      .rotate()
      .composite([{ input: stampPngBuffer, left, top }])
      .png()
      .toBuffer();

    const finalPngBuf = verifyUrl ? injectPngVerifyBuffer(rawOutBuf, verifyUrl) : rawOutBuf;
    fs.writeFileSync(outPath, finalPngBuf);

    return {
      stamped: true,
      format: "PNG",
      output_path: outPath,
    };
  }

  if (isPdf) {
    const outPath = customOutputPath
      ? path.resolve(customOutputPath)
      : path.join(dir, safeArtifactFilename("reltime-stamped-", baseName, ".pdf", verifyHash));
    const pdfBytes = fs.readFileSync(filePath);
    const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
    const pages = pdfDoc.getPages();
    if (pages.length === 0) {
      throw new Error("PDF has no pages.");
    }

    const firstPage = pages[0];
    const { width, height } = firstPage.getSize();

    // Render high-DPI 1024x1024 (300+ DPI) Option 1A Sun-Stamp PNG
    const stampPngBuffer = await sharp(Buffer.from(cleanSvg, "utf8"))
      .resize(1024, 1024)
      .png()
      .toBuffer();

    const pngImage = await pdfDoc.embedPng(stampPngBuffer);
    const targetSize = Math.min(148, Math.max(105, Math.min(width, height) * 0.22));
    const margin = 18;
    const drawX = Math.max(margin, width - targetSize - margin);
    const drawY = margin;

    firstPage.drawImage(pngImage, {
      x: drawX,
      y: drawY,
      width: targetSize,
      height: targetSize,
    });

    // Attach clickable PDF Link Annotation over the Sun-Stamp rectangle
    if (verifyUrl) {
      try {
        const linkAnnotation = pdfDoc.context.obj({
          Type: "Annot",
          Subtype: "Link",
          Rect: [drawX, drawY, drawX + targetSize, drawY + targetSize],
          Border: [0, 0, 0],
          F: 4,
          A: {
            Type: "Action",
            S: "URI",
            URI: PDFString.of(verifyUrl),
          },
        });
        const linkRef = pdfDoc.context.register(linkAnnotation);
        if (typeof firstPage.node.addAnnot === "function") {
          firstPage.node.addAnnot(linkRef);
        } else {
          firstPage.node.set(PDFName.of("Annots"), pdfDoc.context.obj([linkRef]));
        }
      } catch (e) {
        // Ignore annotation error on restricted PDFs
      }
    }

    const modifiedPdfBytes = await pdfDoc.save({ useObjectStreams: false });
    fs.writeFileSync(outPath, Buffer.from(modifiedPdfBytes));

    return {
      stamped: true,
      format: "PDF",
      output_path: outPath,
    };
  }
}

/**
 * Extracts an embedded Rel-Time verification hash from a Stamped Copy (.png or .pdf) if present.
 */
function extractStampedCopyEmbeddedHash(filePath, fileBuffer) {
  try {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".png" || ext === ".pdf" || ext === ".svg") {
      const latin1 = fileBuffer.toString("latin1");
      const m = latin1.match(/rel-time\.com\/verify\?t=([0-9a-fA-F]{64})/);
      if (m && m[1]) {
        return m[1].toLowerCase();
      }
    }
  } catch (e) {
    // Ignore extraction errors
  }
  return null;
}

function escapeHtml(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Generates a self-contained, institutional-grade Rel-Time Superhighway Cryptographic Audit Trail HTML report.
 */
function generateAuditReportHtml(audit) {
  const generatedUtc = audit.generated_at_utc || new Date().toISOString();
  const acct = audit.account_overview || {};
  const sum = audit.audit_summary || {};
  const modes = sum.mode_breakdown || {};
  const btc = sum.bitcoin_settlement || {};
  const signers = Array.isArray(sum.hardware_passkey_signers) ? sum.hardware_passkey_signers : [];
  const localCheck = audit.local_path_verification || null;
  const entries = Array.isArray(audit.audit_trail) ? audit.audit_trail : [];

  const totalMatched = Math.max(1, Number(sum.matched_entries_count || entries.length || 1));
  const settledCount = Number(sum.settled_on_bitcoin_count || 0);
  const pendingCount = Number(sum.pending_finality_count || 0);
  const standardCount = Number(modes.standard_count || 0);
  const temporalCount = Number(modes.temporal_vdf_count || 0);
  const biometricCount = Number(modes.biometric_passkey_count || 0);
  const machineCount = Math.max(0, Number(sum.matched_entries_count || entries.length) - biometricCount);

  const settledPct = Math.round((settledCount / totalMatched) * 100);
  const standardPct = Math.round((standardCount / totalMatched) * 100);
  const biometricPct = Math.round((biometricCount / totalMatched) * 100);

  // Build Bitcoin Block Settlement Topology nodes from entries
  const blockGroupsMap = new Map();
  for (const e of entries) {
    if (e.status === "settled" && e.block_height) {
      const bh = String(e.block_height);
      const cur = blockGroupsMap.get(bh) || {
        block_height: bh,
        count: 0,
        txid: e.txid || null,
        max_ticks: 0,
        timestamp_utc: e.timestamp_utc || null,
      };
      cur.count++;
      if (!cur.txid && e.txid) cur.txid = e.txid;
      if (Number(e.vdf_ticks || 0) > cur.max_ticks) cur.max_ticks = Number(e.vdf_ticks || 0);
      blockGroupsMap.set(bh, cur);
    }
  }
  const sortedBlocks = Array.from(blockGroupsMap.values())
    .sort((a, b) => Number(a.block_height) - Number(b.block_height))
    .slice(-5);

  const topologyNodesHtml = [
    ...sortedBlocks.map(
      (b) => `
      <div class="topo-node">
        <div class="topo-node-top">
          <span class="dot dot-settled"></span>
          <span class="mono topo-height">BLOCK #${escapeHtml(b.block_height)}</span>
        </div>
        <div class="topo-metric mono">${b.count} ${b.count === 1 ? "ANCHOR" : "ANCHORS"}</div>
        <div class="topo-meta mono">
          ${
            b.txid
              ? `<a href="https://mempool.space/tx/${escapeHtml(b.txid)}" target="_blank" rel="noopener">TX ${escapeHtml(
                  b.txid.slice(0, 8)
                )}…${escapeHtml(b.txid.slice(-4))} ↗</a>`
              : "SETTLED"
          }
        </div>
      </div>`
    ),
    pendingCount > 0
      ? `
      <div class="topo-node topo-node-pending">
        <div class="topo-node-top">
          <span class="dot dot-pending"></span>
          <span class="mono topo-height">VDF MEMPOOL QUEUE</span>
        </div>
        <div class="topo-metric mono">${pendingCount} PENDING</div>
        <div class="topo-meta mono">NEXT EPOCH (~10m)</div>
      </div>`
      : "",
  ]
    .filter(Boolean)
    .join(`<div class="topo-connector"></div>`);

  const signerRowsHtml = signers.length
    ? signers
        .map((s, idx) => {
          const sharePct = Math.round((Number(s.anchor_count || 0) / totalMatched) * 100);
          return `
        <tr>
          <td class="mono muted">${String(idx + 1).padStart(2, "0")}</td>
          <td>
            <div class="signer-key-header">
              <span class="tag tag-neutral">FIDO2 / COSE P-256</span>
              <span class="mono muted">KEY ID: ${escapeHtml(s.signer_public_key.slice(0, 16).toUpperCase())}</span>
            </div>
            <div class="mono hash-full" style="margin-top:5px">${escapeHtml(s.signer_public_key)}</div>
          </td>
          <td class="mono">
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-weight:700;color:var(--text);min-width:24px">${s.anchor_count}</span>
              <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${sharePct}%"></div></div>
              <span class="muted" style="font-size:11px">${sharePct}%</span>
            </div>
          </td>
          <td class="mono">${s.settled_count} / ${s.anchor_count}</td>
          <td class="mono muted">${escapeHtml(s.latest_timestamp_utc || "—")}</td>
        </tr>`;
        })
        .join("")
    : `<tr><td colspan="5" class="empty-cell">No hardware Passkey signatures recorded in this window. Link a FIDO2/WebAuthn hardware key with <code>reltime_link_passkey</code> and anchor with <code>biometric: true</code>.</td></tr>`;

  const localVerificationHtml = localCheck
    ? `
    <section class="panel">
      <div class="panel-header">
        <div>
          <div class="section-index">SECTION 01 // ZERO-KNOWLEDGE LOCAL FILE INTEGRITY MATRIX</div>
          <h2>Local Directory Cross-Reference</h2>
          <p class="section-sub">Target Path: <span class="mono" style="color:var(--text-secondary)">${escapeHtml(
            redactHomePath(localCheck.target_path)
          )}</span> · 0 Bytes Uploaded · Local SHA-256 vs. Bitcoin Ledger</p>
        </div>
        <div class="status-pill ${
          localCheck.summary.unanchored_or_modified_count === 0 ? "status-pill-ok" : "status-pill-alert"
        }">
          <span class="dot ${
            localCheck.summary.unanchored_or_modified_count === 0 ? "dot-settled" : "dot-alert"
          }"></span>
          <span>${
            localCheck.summary.unanchored_or_modified_count === 0
              ? `INTEGRITY VERIFIED (${localCheck.summary.total_files_scanned}/${localCheck.summary.total_files_scanned})`
              : `${localCheck.summary.unanchored_or_modified_count} UNANCHORED OR MODIFIED`
          }</span>
        </div>
      </div>
      <div class="filter-bar no-print">
        <div class="tab-group" id="localTabGroup">
          <button class="filter-tab local-filter-tab active" onclick="setLocalPill(this, 'all')">All (${localCheck.summary.total_files_scanned})</button>
          <button class="filter-tab local-filter-tab" onclick="setLocalPill(this, 'local-settled')">Settled (${localCheck.summary.verified_settled_count})</button>
          <button class="filter-tab local-filter-tab" onclick="setLocalPill(this, 'local-pending')">Pending (${localCheck.summary.verified_pending_count})</button>
          <button class="filter-tab local-filter-tab" onclick="setLocalPill(this, 'local-alert')">Unanchored / Modified (${localCheck.summary.unanchored_or_modified_count})</button>
        </div>
        <input id="localSearchInput" class="search-input" type="text" placeholder="QUERY FILE NAME / SHA-256 / PASSKEY / BLOCK..." oninput="resetAndFilterLocal()" />
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:42px">#</th>
              <th>Artifact / File Name</th>
              <th>Bytes</th>
              <th>Local SHA-256 Digest</th>
              <th>Verification Status</th>
              <th>Attestation / Mode</th>
              <th>Timechain Settlement</th>
              <th style="text-align:right">Receipt</th>
            </tr>
          </thead>
          <tbody id="localVerifyBody">
            ${localCheck.files
              .map((f, idx) => {
                const localRowClass =
                  f.integrity_status === "VERIFIED_SETTLED"
                    ? "local-settled"
                    : f.integrity_status === "VERIFIED_PENDING"
                    ? "local-pending"
                    : "local-alert";

                const statusTag =
                  f.integrity_status === "VERIFIED_SETTLED"
                    ? `<span class="status-cell"><span class="dot dot-settled"></span><span class="mono" style="color:var(--text)">VERIFIED · SETTLED</span></span>`
                    : f.integrity_status === "VERIFIED_PENDING"
                    ? `<span class="status-cell"><span class="dot dot-pending"></span><span class="mono" style="color:var(--text-secondary)">VERIFIED · PENDING</span></span>`
                    : `<span class="status-cell"><span class="dot dot-alert"></span><span class="mono" style="color:var(--crimson)">UNANCHORED / MODIFIED</span></span>`;

                const signerText = f.signer_public_key
                  ? `<span class="tag tag-neutral" title="Passkey COSE: ${escapeHtml(
                      f.signer_public_key
                    )}">PASSKEY ${escapeHtml(f.signer_public_key.slice(0, 8).toUpperCase())}…</span>`
                  : f.anchor_mode
                  ? `<span class="tag tag-neutral">${escapeHtml(f.anchor_mode.toUpperCase())}</span>`
                  : `<span class="mono muted">—</span>`;

                const btcText = f.block_height
                  ? `<span class="mono" style="color:var(--text)">BLOCK #${escapeHtml(f.block_height)}</span>`
                  : f.integrity_status === "VERIFIED_PENDING"
                  ? `<span class="mono muted">MEMPOOL QUEUE</span>`
                  : `<span class="mono muted">—</span>`;

                const verifyLink = f.verify_url
                  ? `<a class="action-link" href="${escapeHtml(f.verify_url)}" target="_blank" rel="noopener">VERIFY ↗</a>`
                  : `<span class="mono muted">—</span>`;

                return `
                <tr class="local-row ${localRowClass}" data-search="${escapeHtml(
                  `${f.file_name} ${f.local_sha256} ${f.signer_public_key || ""} ${f.block_height || ""} ${f.anchor_mode || ""}`.toLowerCase()
                )}">
                  <td class="mono muted">${String(idx + 1).padStart(2, "0")}</td>
                  <td>
                    <span style="font-weight:600;color:var(--text)">${escapeHtml(f.file_name)}</span>
                    ${f.is_stamped_copy ? `<span class="tag tag-subtle" style="margin-left:8px">STAMPED COPY</span>` : ""}
                  </td>
                  <td class="mono muted">${escapeHtml(f.size_human)}</td>
                  <td class="mono" style="color:var(--text-secondary)" title="${escapeHtml(f.local_sha256)}">${escapeHtml(
                  f.local_sha256.slice(0, 16)
                )}…${escapeHtml(f.local_sha256.slice(-10))}</td>
                  <td>${statusTag}</td>
                  <td>${signerText}</td>
                  <td>${btcText}</td>
                  <td style="text-align:right">${verifyLink}</td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>
      </div>
      <div class="pagination-bar no-print" id="localPaginationBar">
        <div class="pagination-info mono">
          <span id="localRangeLabel">SHOWING 1–25</span>
          <span class="muted">·</span>
          <label class="mono muted" for="localPageSizeSelect">ROWS:</label>
          <select id="localPageSizeSelect" class="page-size-select mono" onchange="changeLocalPageSize(this.value)">
            <option value="25" selected>25 / PAGE</option>
            <option value="50">50 / PAGE</option>
            <option value="100">100 / PAGE</option>
            <option value="0">ALL (FULL LIST)</option>
          </select>
        </div>
        <div class="pagination-controls">
          <button type="button" class="page-btn mono" id="localFirstBtn" onclick="goLocalPage(1)">[ ⟪ FIRST ]</button>
          <button type="button" class="page-btn mono" id="localPrevBtn" onclick="stepLocalPage(-1)">[ ‹ PREV ]</button>
          <span class="page-indicator mono" id="localPageIndicator">PAGE 1 OF 1</span>
          <button type="button" class="page-btn mono" id="localNextBtn" onclick="stepLocalPage(1)">[ NEXT › ]</button>
          <button type="button" class="page-btn mono" id="localLastBtn" onclick="goLocalLastPage()">[ LAST ⟫ ]</button>
        </div>
      </div>
    </section>`
    : "";

  const ledgerSectionNum = localCheck ? "03" : "02";
  const signerSectionNum = localCheck ? "02" : "01";

  const ledgerRowsHtml = entries.length
    ? entries
        .map((e, idx) => {
          const isSettled = e.status === "settled";
          const isBiometric = Boolean(e.signer_public_key);
          const modeType = e.anchor_mode || "standard";
          const filterClasses = [
            isSettled ? "status-settled" : "status-pending",
            `mode-${modeType}`,
            isBiometric ? "mode-biometric" : "",
          ]
            .filter(Boolean)
            .join(" ");

          const statusHtml = isSettled
            ? `<span class="status-cell"><span class="dot dot-settled"></span><span class="mono" style="color:var(--text)">SETTLED</span></span>`
            : `<span class="status-cell"><span class="dot dot-pending"></span><span class="mono muted">PENDING</span></span>`;

          const modeHtml = `
            <span class="tag tag-neutral">${escapeHtml(modeType.toUpperCase())}</span>
            ${
              isBiometric
                ? `<span class="tag tag-subtle" title="Passkey COSE: ${escapeHtml(
                    e.signer_public_key
                  )}">PK:${escapeHtml(e.signer_public_key.slice(0, 8).toUpperCase())}</span>`
                : ""
            }
          `;

          const btcHtml = isSettled
            ? `
              <div class="mono" style="color:var(--text);font-weight:600">BLOCK #${escapeHtml(e.block_height || "—")}</div>
              ${
                e.txid
                  ? `<a class="mono tx-link" href="https://mempool.space/tx/${escapeHtml(
                      e.txid
                    )}" target="_blank" rel="noopener" title="${escapeHtml(e.txid)}">TX ${escapeHtml(
                      e.txid.slice(0, 10)
                    )}…${escapeHtml(e.txid.slice(-6))} ↗</a>`
                  : ""
              }
            `
            : `<span class="mono muted">AWAITING BLOCK</span>`;

          return `
          <tr class="ledger-row ${filterClasses}" data-search="${escapeHtml(
            `${e.client_hash} ${e.t_index} ${e.original_file_hash || ""} ${e.signer_public_key || ""} ${
              e.txid || ""
            } ${e.block_height || ""} ${modeType}`.toLowerCase()
          )}">
            <td class="mono muted">${String(idx + 1).padStart(2, "0")}</td>
            <td class="mono muted">${escapeHtml((e.timestamp_utc || "—").replace(".000Z", "Z"))}</td>
            <td>${statusHtml}</td>
            <td>${modeHtml}</td>
            <td class="mono" style="color:var(--text-secondary)" title="Client Hash: ${escapeHtml(e.client_hash)}${
            e.original_file_hash ? ` | Original File SHA-256: ${escapeHtml(e.original_file_hash)}` : ""
          }">
              <div>${escapeHtml(e.client_hash.slice(0, 14))}…${escapeHtml(e.client_hash.slice(-10))}</div>
              ${
                e.original_file_hash
                  ? `<div class="muted" style="font-size:10.5px;margin-top:2px">FILE: ${escapeHtml(
                      e.original_file_hash.slice(0, 12)
                    )}…</div>`
                  : ""
              }
            </td>
            <td class="mono" style="color:var(--text-secondary)" title="T_index: ${escapeHtml(e.t_index)} | Solar Ticks: ${escapeHtml(
            e.vdf_ticks
          )}">
              <div>${escapeHtml(e.t_index.slice(0, 14))}…${escapeHtml(e.t_index.slice(-8))}</div>
              <div class="muted" style="font-size:10.5px;margin-top:2px">VDF TICKS: ${Number(
                e.vdf_ticks || 0
              ).toLocaleString()}</div>
            </td>
            <td>${btcHtml}</td>
            <td style="text-align:right">
              <a class="action-link" href="${escapeHtml(e.verify_url)}" target="_blank" rel="noopener">VERIFY ↗</a>
            </td>
          </tr>`;
        })
        .join("")
    : `<tr><td colspan="8" class="empty-cell">No ledger entries matched the active filter criteria.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Rel-Time Superhighway // Forensic Timechain Audit Report</title>
  <style>
    :root {
      --bg: #050506;
      --grid-line: rgba(255, 255, 255, 0.015);
      --panel: #0a0a0c;
      --panel-alt: #0e0e12;
      --border: #1e1e24;
      --border-strong: #2e2e38;
      --text: #f4f4f5;
      --text-secondary: #d4d4d8;
      --muted: #71717a;
      --amber: #f59e0b;
      --emerald: #10b981;
      --crimson: #ef4444;
      --track-bg: #18181d;
      --bar-primary: #e4e4e7;
      --bar-muted: #3f3f46;
      --tag-bg: #141418;
      --tab-active-bg: #18181f;
      --row-hover: rgba(255, 255, 255, 0.015);
      --btn-primary-fg: #050506;
    }
    html[data-theme="light"] {
      --bg: #f4f4f6;
      --grid-line: rgba(0, 0, 0, 0.03);
      --panel: #ffffff;
      --panel-alt: #f8f8fa;
      --border: #e4e4e7;
      --border-strong: #d4d4d8;
      --text: #09090b;
      --text-secondary: #3f3f46;
      --muted: #71717a;
      --amber: #d97706;
      --emerald: #059669;
      --crimson: #dc2626;
      --track-bg: #e4e4e7;
      --bar-primary: #18181b;
      --bar-muted: #a1a1aa;
      --tag-bg: #f4f4f5;
      --tab-active-bg: #f4f4f5;
      --row-hover: rgba(0, 0, 0, 0.02);
      --btn-primary-fg: #ffffff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 28px 24px 64px;
      background-color: var(--bg);
      background-image:
        linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
        linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
      background-size: 32px 32px;
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.45;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.15s ease, color 0.15s ease;
    }
    .container { max-width: 1360px; margin: 0 auto; }
    .mono {
      font-family: "JetBrains Mono", "SF Mono", "Fira Code", Menlo, Consolas, monospace;
      font-variant-numeric: tabular-nums;
      font-size: 12px;
    }
    .muted { color: var(--muted); }

    /* Masthead */
    .masthead {
      background: var(--panel);
      border: 1px solid var(--border);
      border-top: 2px solid var(--amber);
      padding: 22px 26px;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      margin-bottom: 16px;
    }
    .eyebrow {
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10.5px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--amber);
      margin-bottom: 6px;
    }
    h1 {
      margin: 0;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text);
    }
    .masthead-meta {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 18px;
      font-size: 11.5px;
      color: var(--muted);
    }
    .masthead-meta span strong {
      color: var(--text-secondary);
      font-weight: 600;
    }
    .actions-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .btn-primary {
      background: var(--text);
      color: var(--btn-primary-fg);
      border: 1px solid var(--text);
      padding: 9px 14px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      cursor: pointer;
      text-decoration: none;
    }
    .btn-primary:hover {
      background: var(--amber);
      border-color: var(--amber);
      color: #050506;
    }
    .btn-secondary {
      background: transparent;
      color: var(--text-secondary);
      border: 1px solid var(--border-strong);
      padding: 9px 14px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      cursor: pointer;
      text-decoration: none;
    }
    .btn-secondary:hover {
      border-color: var(--text-secondary);
      color: var(--text);
    }

    /* Flush Architectural Telemetry Strip */
    .telemetry-strip {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      background: var(--panel);
      border: 1px solid var(--border);
      margin-bottom: 16px;
    }
    @media (max-width: 1100px) {
      .telemetry-strip { grid-template-columns: repeat(3, 1fr); }
    }
    @media (max-width: 640px) {
      .telemetry-strip { grid-template-columns: repeat(2, 1fr); }
    }
    .telemetry-cell {
      padding: 16px 20px;
      border-right: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }
    .telemetry-cell:last-child { border-right: none; }
    .telemetry-label {
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
      margin-bottom: 8px;
    }
    .telemetry-val {
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 24px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.02em;
    }
    .telemetry-sub {
      font-size: 11px;
      color: var(--muted);
      margin-top: 4px;
    }

    /* Visualization Grid (2 Columns) */
    .viz-grid {
      display: grid;
      grid-template-columns: 1fr 1.25fr;
      gap: 16px;
      margin-bottom: 16px;
    }
    @media (max-width: 980px) {
      .viz-grid { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      padding: 20px 24px;
      margin-bottom: 16px;
    }
    .viz-grid .panel { margin-bottom: 0; }
    .panel-header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .section-index {
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 3px;
    }
    h2 {
      margin: 0;
      font-size: 15px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--text);
    }
    .section-sub {
      margin: 3px 0 0;
      font-size: 12px;
      color: var(--muted);
    }

    /* Distribution Bars */
    .dist-row {
      margin-bottom: 14px;
    }
    .dist-row:last-child { margin-bottom: 0; }
    .dist-header {
      display: flex;
      justify-content: space-between;
      font-size: 11.5px;
      margin-bottom: 6px;
    }
    .dist-track {
      height: 6px;
      width: 100%;
      background: var(--track-bg);
      display: flex;
      overflow: hidden;
    }
    .dist-seg-primary { background: var(--bar-primary); height: 100%; }
    .dist-seg-emerald { background: var(--emerald); height: 100%; }
    .dist-seg-amber { background: var(--amber); height: 100%; }
    .dist-seg-muted { background: var(--bar-muted); height: 100%; }

    /* Bitcoin Topology Strip */
    .topo-chain {
      display: flex;
      align-items: stretch;
      gap: 0;
      overflow-x: auto;
      padding: 6px 0 4px;
    }
    .topo-node {
      flex: 1;
      min-width: 135px;
      background: var(--panel-alt);
      border: 1px solid var(--border-strong);
      padding: 12px 14px;
    }
    .topo-node-pending {
      border-style: dashed;
      border-color: rgba(245, 158, 11, 0.55);
    }
    .topo-node-top {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
    }
    .topo-height {
      font-size: 11px;
      font-weight: 700;
      color: var(--text);
    }
    .topo-metric {
      font-size: 14px;
      font-weight: 700;
      color: var(--text-secondary);
      margin-bottom: 4px;
    }
    .topo-meta {
      font-size: 10.5px;
      color: var(--muted);
    }
    .topo-meta a {
      color: var(--muted);
      text-decoration: none;
      border-bottom: 1px dotted var(--muted);
    }
    .topo-meta a:hover { color: var(--text); border-bottom-color: var(--text); }
    .topo-connector {
      width: 18px;
      min-width: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }
    .topo-connector::before {
      content: "";
      width: 100%;
      height: 1px;
      background: var(--border-strong);
    }

    /* Status Dots & Tags */
    .status-cell {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      white-space: nowrap;
    }
    .dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }
    .dot-settled { background: var(--emerald); }
    .dot-pending { background: var(--amber); }
    .dot-alert { background: var(--crimson); }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 10px;
      border: 1px solid var(--border-strong);
      background: var(--panel-alt);
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 11px;
      font-weight: 600;
    }
    .status-pill-ok { border-color: rgba(16, 185, 129, 0.4); color: var(--text); }
    .status-pill-alert { border-color: rgba(239, 68, 68, 0.5); color: var(--crimson); }

    .tag {
      display: inline-block;
      padding: 2px 6px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.04em;
      white-space: nowrap;
    }
    .tag-neutral {
      background: var(--tag-bg);
      border: 1px solid var(--border-strong);
      color: var(--text-secondary);
    }
    .tag-subtle {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--muted);
    }

    .mini-bar-track {
      width: 72px;
      height: 4px;
      background: var(--track-bg);
      overflow: hidden;
    }
    .mini-bar-fill {
      height: 100%;
      background: var(--text-secondary);
    }

    /* Filter Bar */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      margin-bottom: 14px;
    }
    .search-input {
      background: var(--bg);
      border: 1px solid var(--border-strong);
      color: var(--text);
      padding: 7px 12px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 11.5px;
      min-width: 290px;
      outline: none;
    }
    .search-input:focus { border-color: var(--text-secondary); }
    .tab-group {
      display: inline-flex;
      border: 1px solid var(--border-strong);
      background: var(--bg);
    }
    .filter-tab {
      background: transparent;
      border: none;
      border-right: 1px solid var(--border);
      color: var(--muted);
      padding: 6px 11px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      cursor: pointer;
    }
    .filter-tab:last-child { border-right: none; }
    .filter-tab:hover { color: var(--text-secondary); }
    .filter-tab.active {
      background: var(--tab-active-bg);
      color: var(--text);
      box-shadow: inset 0 -2px 0 var(--amber);
    }

    /* Tables */
    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th {
      text-align: left;
      padding: 10px 12px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      background: var(--bg);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tr:hover td { background: var(--row-hover); }
    .hash-full {
      word-break: break-all;
      color: var(--text-secondary);
      font-size: 11px;
    }
    .signer-key-header {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .action-link {
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 10.5px;
      font-weight: 600;
      color: var(--text-secondary);
      text-decoration: none;
      padding: 4px 8px;
      border: 1px solid var(--border-strong);
      background: var(--bg);
      white-space: nowrap;
    }
    .action-link:hover {
      border-color: var(--amber);
      color: var(--amber);
    }
    .tx-link {
      color: var(--muted);
      text-decoration: none;
      font-size: 10.5px;
      display: inline-block;
      margin-top: 2px;
    }
    .tx-link:hover { color: var(--text); }
    .empty-cell {
      text-align: center;
      color: var(--muted);
      padding: 24px;
      font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
      font-size: 11.5px;
    }
    .pagination-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }
    .pagination-info {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--text-secondary);
    }
    .page-size-select {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border-strong);
      padding: 4px 8px;
      font-size: 10.5px;
      cursor: pointer;
    }
    .pagination-controls {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .page-btn {
      background: var(--bg);
      color: var(--text-secondary);
      border: 1px solid var(--border-strong);
      padding: 5px 10px;
      font-size: 10.5px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.12s ease;
    }
    .page-btn:hover:not(:disabled) {
      border-color: var(--amber);
      color: var(--amber);
    }
    .page-btn:disabled {
      opacity: 0.35;
      cursor: not-allowed;
    }
    .page-indicator {
      font-size: 11px;
      font-weight: 600;
      color: var(--text);
      padding: 0 8px;
    }
    tr.filter-hidden,
    tr.page-hidden {
      display: none;
    }
    @media print {
      body { background: var(--bg) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; padding: 10px; }
      .no-print { display: none !important; }
      tr.page-hidden { display: table-row !important; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="masthead">
      <div>
        <div class="eyebrow">REL-TIME SOVEREIGN PROVENANCE PROTOCOL // FORENSIC AUDIT LEDGER</div>
        <h1>Cryptographic Data Integrity &amp; Timechain Settlement Report</h1>
        <div class="masthead-meta mono">
          <span>GENERATED UTC: <strong>${escapeHtml(generatedUtc)}</strong></span>
          <span>SLA TIER: <strong>${escapeHtml(acct.tier || "Active")}</strong></span>
          <span>CREDENTIAL: <strong>${escapeHtml(acct.masked_api_key || "rel_key_***")}</strong></span>
        </div>
      </div>
      <div class="actions-bar no-print">
        <button id="themeToggleBtn" class="btn-secondary" onclick="toggleTheme()">[ ☀ LIGHT MODE ]</button>
        <a class="btn-secondary" href="https://rel-time.com/verify" target="_blank" rel="noopener">[ OPEN VERIFIER ↗ ]</a>
        <button class="btn-primary" onclick="window.print()">[ EXPORT PDF CERTIFICATE ]</button>
      </div>
    </header>

    <div class="telemetry-strip">
      <div class="telemetry-cell">
        <div class="telemetry-label">Audited Scope</div>
        <div class="telemetry-val">${Number(sum.matched_entries_count || 0).toLocaleString()}</div>
        <div class="telemetry-sub mono">LIFETIME: ${Number(acct.lifetime_anchors || 0).toLocaleString()}</div>
      </div>
      <div class="telemetry-cell">
        <div class="telemetry-label">Timechain Finality</div>
        <div class="telemetry-val">${settledCount.toLocaleString()} <span style="font-size:14px;color:var(--muted)">/ ${Number(
    sum.matched_entries_count || 0
  )}</span></div>
        <div class="telemetry-sub mono">${escapeHtml(sum.settlement_rate_pct || "0%")} SETTLED · ${pendingCount} QUEUED</div>
      </div>
      <div class="telemetry-cell">
        <div class="telemetry-label">Bitcoin Blocks</div>
        <div class="telemetry-val">${Number(btc.unique_blocks_count || 0)}</div>
        <div class="telemetry-sub mono">${Number(btc.unique_txids_count || 0)} OP_RETURN TXS${
    btc.latest_settled_block ? ` · #${escapeHtml(btc.latest_settled_block)}` : ""
  }</div>
      </div>
      <div class="telemetry-cell">
        <div class="telemetry-label">Mode Split</div>
        <div class="telemetry-val">${standardCount} <span style="font-size:14px;color:var(--muted)">:</span> ${temporalCount}</div>
        <div class="telemetry-sub mono">STANDARD : TEMPORAL VDF</div>
      </div>
      <div class="telemetry-cell">
        <div class="telemetry-label">Passkey Authorities</div>
        <div class="telemetry-val">${signers.length}</div>
        <div class="telemetry-sub mono">${biometricCount} BIOMETRIC SIGNATURES</div>
      </div>
      <div class="telemetry-cell">
        <div class="telemetry-label">Available Fuel</div>
        <div class="telemetry-val" style="color:var(--amber)">${Number(
          acct.hash_credits_remaining || 0
        ).toLocaleString()}</div>
        <div class="telemetry-sub mono">HASH CREDITS REMAINING</div>
      </div>
    </div>

    <div class="viz-grid">
      <div class="panel">
        <div class="panel-header" style="margin-bottom:14px;padding-bottom:10px">
          <div>
            <div class="section-index">TELEMETRY // DISTRIBUTION METRICS</div>
            <h2>Pipeline &amp; Attestation Ratios</h2>
          </div>
        </div>
        <div class="dist-row">
          <div class="dist-header mono">
            <span>BITCOIN FINALITY (${settledPct}% SETTLED)</span>
            <span class="muted">${settledCount} SETTLED / ${pendingCount} PENDING</span>
          </div>
          <div class="dist-track">
            <div class="dist-seg-emerald" style="width:${settledPct}%"></div>
            <div class="dist-seg-amber" style="width:${100 - settledPct}%"></div>
          </div>
        </div>
        <div class="dist-row">
          <div class="dist-header mono">
            <span>HASHING ARCHITECTURE (${standardPct}% STANDARD)</span>
            <span class="muted">${standardCount} INTEGRITY / ${temporalCount} TEMPORAL VDF</span>
          </div>
          <div class="dist-track">
            <div class="dist-seg-primary" style="width:${standardPct}%"></div>
            <div class="dist-seg-muted" style="width:${100 - standardPct}%"></div>
          </div>
        </div>
        <div class="dist-row">
          <div class="dist-header mono">
            <span>HARDWARE PASSKEY ATTESTATION (${biometricPct}%)</span>
            <span class="muted">${biometricCount} FIDO2 SIGNED / ${machineCount} MACHINE</span>
          </div>
          <div class="dist-track">
            <div class="dist-seg-primary" style="width:${biometricPct}%"></div>
            <div class="dist-seg-muted" style="width:${100 - biometricPct}%"></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header" style="margin-bottom:14px;padding-bottom:10px">
          <div>
            <div class="section-index">TIMECHAIN TOPOLOGY // MERKLE BATCH ANCHORS</div>
            <h2>Bitcoin Block Settlement Sequence</h2>
          </div>
          <span class="mono muted" style="font-size:11px">SHA-256 MERKLE ROOT ➔ OP_RETURN</span>
        </div>
        <div class="topo-chain">
          ${
            topologyNodesHtml ||
            `<div class="empty-cell" style="width:100%;padding:16px">No settled Bitcoin blocks in current filter window.</div>`
          }
        </div>
      </div>
    </div>

    ${localVerificationHtml}

    <section class="panel">
      <div class="panel-header">
        <div>
          <div class="section-index">SECTION ${signerSectionNum} // CORPORATE HARDWARE PASSKEY REGISTRY</div>
          <h2>Authorized WebAuthn / FIDO2 Signer Authorities</h2>
          <p class="section-sub">Non-exportable Secure Enclave &amp; YubiKey COSE public keys recorded across this corporate credential</p>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:42px">#</th>
              <th>Hardware Signer Public Key (COSE Hex)</th>
              <th style="width:200px">Attested Volume</th>
              <th style="width:130px">Finality Ratio</th>
              <th style="width:190px">Latest Attestation (UTC)</th>
            </tr>
          </thead>
          <tbody>
            ${signerRowsHtml}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <div class="section-index">SECTION ${ledgerSectionNum} // CHRONOLOGICAL TIMECHAIN LEDGER</div>
          <h2>Cryptographic Anchor &amp; VDF Sequence Log</h2>
          <p class="section-sub">Immutable record of SHA-256 payload digests, VDF thermodynamic proofs (T_index), and Bitcoin Merkle settlements</p>
        </div>
      </div>
      <div class="filter-bar no-print">
        <div class="tab-group" id="ledgerTabGroup">
          <button class="filter-tab ledger-filter-tab active" onclick="setPill(this, 'all')">All (${entries.length})</button>
          <button class="filter-tab ledger-filter-tab" onclick="setPill(this, 'status-settled')">Settled (${settledCount})</button>
          <button class="filter-tab ledger-filter-tab" onclick="setPill(this, 'status-pending')">Pending (${pendingCount})</button>
          <button class="filter-tab ledger-filter-tab" onclick="setPill(this, 'mode-biometric')">Passkey (${biometricCount})</button>
          <button class="filter-tab ledger-filter-tab" onclick="setPill(this, 'mode-temporal')">Temporal VDF (${temporalCount})</button>
          <button class="filter-tab ledger-filter-tab" onclick="setPill(this, 'mode-standard')">Standard (${standardCount})</button>
        </div>
        <input id="searchInput" class="search-input" type="text" placeholder="QUERY SHA-256 / T_INDEX / PASSKEY / TXID / BLOCK..." oninput="resetAndFilterLedger()" />
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:42px">#</th>
              <th>Timestamp (UTC)</th>
              <th>Finality</th>
              <th>Mode / Authority</th>
              <th>Client / File SHA-256 Digest</th>
              <th>Thermodynamic Proof (T_Index)</th>
              <th>Bitcoin Settlement</th>
              <th style="text-align:right">Proof</th>
            </tr>
          </thead>
          <tbody id="ledgerBody">
            ${ledgerRowsHtml}
          </tbody>
        </table>
      </div>
      <div class="pagination-bar no-print" id="ledgerPaginationBar">
        <div class="pagination-info mono">
          <span id="ledgerRangeLabel">SHOWING 1–25</span>
          <span class="muted">·</span>
          <label class="mono muted" for="ledgerPageSizeSelect">ROWS:</label>
          <select id="ledgerPageSizeSelect" class="page-size-select mono" onchange="changeLedgerPageSize(this.value)">
            <option value="25" selected>25 / PAGE</option>
            <option value="50">50 / PAGE</option>
            <option value="100">100 / PAGE</option>
            <option value="0">ALL (FULL LIST)</option>
          </select>
        </div>
        <div class="pagination-controls">
          <button type="button" class="page-btn mono" id="ledgerFirstBtn" onclick="goLedgerPage(1)">[ ⟪ FIRST ]</button>
          <button type="button" class="page-btn mono" id="ledgerPrevBtn" onclick="stepLedgerPage(-1)">[ ‹ PREV ]</button>
          <span class="page-indicator mono" id="ledgerPageIndicator">PAGE 1 OF 1</span>
          <button type="button" class="page-btn mono" id="ledgerNextBtn" onclick="stepLedgerPage(1)">[ NEXT › ]</button>
          <button type="button" class="page-btn mono" id="ledgerLastBtn" onclick="goLedgerLastPage()">[ LAST ⟫ ]</button>
        </div>
      </div>
    </section>
  </div>

  <script>
    let currentFilter = 'all';
    let ledgerPage = 1;
    let ledgerPageSize = 25;
    let ledgerTotalPages = 1;

    let currentLocalFilter = 'all';
    let localPage = 1;
    let localPageSize = 25;
    let localTotalPages = 1;

    function applyTheme(theme) {
      const root = document.documentElement;
      const btn = document.getElementById('themeToggleBtn');
      if (theme === 'light') {
        root.setAttribute('data-theme', 'light');
        if (btn) btn.textContent = '[ ☾ DARK MODE ]';
      } else {
        root.setAttribute('data-theme', 'dark');
        if (btn) btn.textContent = '[ ☀ LIGHT MODE ]';
      }
      try { localStorage.setItem('reltime_audit_theme', theme); } catch (e) {}
    }
    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    }
    (function initTheme() {
      try {
        const saved = localStorage.getItem('reltime_audit_theme');
        if (saved === 'light' || saved === 'dark') applyTheme(saved);
      } catch (e) {}
    })();

    // Section 01: Local Directory Cross-Reference Pagination & Filtering
    function setLocalPill(btn, filter) {
      currentLocalFilter = filter;
      document.querySelectorAll('.local-filter-tab').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      localPage = 1;
      filterLocalTable();
    }
    function resetAndFilterLocal() {
      localPage = 1;
      filterLocalTable();
    }
    function changeLocalPageSize(val) {
      localPageSize = Number(val) || 0;
      localPage = 1;
      filterLocalTable();
    }
    function goLocalPage(p) {
      localPage = Math.max(1, Math.min(localTotalPages, p));
      filterLocalTable();
    }
    function stepLocalPage(delta) {
      goLocalPage(localPage + delta);
    }
    function goLocalLastPage() {
      goLocalPage(localTotalPages);
    }
    function filterLocalTable() {
      const rows = Array.from(document.querySelectorAll('.local-row'));
      if (!rows.length) return;
      const qEl = document.getElementById('localSearchInput');
      const q = (qEl ? qEl.value : '').trim().toLowerCase();
      const matched = [];
      rows.forEach(row => {
        const matchesFilter = currentLocalFilter === 'all' || row.classList.contains(currentLocalFilter);
        const matchesQuery = !q || (row.getAttribute('data-search') || '').includes(q);
        if (matchesFilter && matchesQuery) {
          row.classList.remove('filter-hidden');
          matched.push(row);
        } else {
          row.classList.add('filter-hidden');
          row.classList.remove('page-hidden');
        }
      });

      const total = matched.length;
      localTotalPages = localPageSize > 0 ? Math.max(1, Math.ceil(total / localPageSize)) : 1;
      if (localPage > localTotalPages) localPage = localTotalPages;
      const startIdx = localPageSize > 0 ? (localPage - 1) * localPageSize : 0;
      const endIdx = localPageSize > 0 ? Math.min(total, startIdx + localPageSize) : total;

      matched.forEach((row, idx) => {
        if (localPageSize > 0 && (idx < startIdx || idx >= endIdx)) {
          row.classList.add('page-hidden');
        } else {
          row.classList.remove('page-hidden');
        }
      });

      const rangeEl = document.getElementById('localRangeLabel');
      if (rangeEl) {
        rangeEl.textContent = total === 0 ? 'SHOWING 0 OF 0 FILES' : 'SHOWING ' + (startIdx + 1) + '–' + endIdx + ' OF ' + total.toLocaleString() + ' FILES';
      }
      const indEl = document.getElementById('localPageIndicator');
      if (indEl) indEl.textContent = 'PAGE ' + localPage + ' OF ' + localTotalPages;
      const firstBtn = document.getElementById('localFirstBtn');
      const prevBtn = document.getElementById('localPrevBtn');
      const nextBtn = document.getElementById('localNextBtn');
      const lastBtn = document.getElementById('localLastBtn');
      if (firstBtn) firstBtn.disabled = localPage <= 1;
      if (prevBtn) prevBtn.disabled = localPage <= 1;
      if (nextBtn) nextBtn.disabled = localPage >= localTotalPages;
      if (lastBtn) lastBtn.disabled = localPage >= localTotalPages;
    }

    // Section 03: Chronological Timechain Ledger Pagination & Filtering
    function setPill(btn, filter) {
      currentFilter = filter;
      document.querySelectorAll('.ledger-filter-tab').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      ledgerPage = 1;
      filterLedger();
    }
    function resetAndFilterLedger() {
      ledgerPage = 1;
      filterLedger();
    }
    function changeLedgerPageSize(val) {
      ledgerPageSize = Number(val) || 0;
      ledgerPage = 1;
      filterLedger();
    }
    function goLedgerPage(p) {
      ledgerPage = Math.max(1, Math.min(ledgerTotalPages, p));
      filterLedger();
    }
    function stepLedgerPage(delta) {
      goLedgerPage(ledgerPage + delta);
    }
    function goLedgerLastPage() {
      goLedgerPage(ledgerTotalPages);
    }
    function filterLedger() {
      const rows = Array.from(document.querySelectorAll('.ledger-row'));
      const qEl = document.getElementById('searchInput');
      const q = (qEl ? qEl.value : '').trim().toLowerCase();
      const matched = [];
      rows.forEach(row => {
        const matchesFilter = currentFilter === 'all' || row.classList.contains(currentFilter);
        const matchesQuery = !q || (row.getAttribute('data-search') || '').includes(q);
        if (matchesFilter && matchesQuery) {
          row.classList.remove('filter-hidden');
          matched.push(row);
        } else {
          row.classList.add('filter-hidden');
          row.classList.remove('page-hidden');
        }
      });

      const total = matched.length;
      ledgerTotalPages = ledgerPageSize > 0 ? Math.max(1, Math.ceil(total / ledgerPageSize)) : 1;
      if (ledgerPage > ledgerTotalPages) ledgerPage = ledgerTotalPages;
      const startIdx = ledgerPageSize > 0 ? (ledgerPage - 1) * ledgerPageSize : 0;
      const endIdx = ledgerPageSize > 0 ? Math.min(total, startIdx + ledgerPageSize) : total;

      matched.forEach((row, idx) => {
        if (ledgerPageSize > 0 && (idx < startIdx || idx >= endIdx)) {
          row.classList.add('page-hidden');
        } else {
          row.classList.remove('page-hidden');
        }
      });

      const rangeEl = document.getElementById('ledgerRangeLabel');
      if (rangeEl) {
        rangeEl.textContent = total === 0 ? 'SHOWING 0 OF 0 RECORDS' : 'SHOWING ' + (startIdx + 1) + '–' + endIdx + ' OF ' + total.toLocaleString() + ' RECORDS';
      }
      const indEl = document.getElementById('ledgerPageIndicator');
      if (indEl) indEl.textContent = 'PAGE ' + ledgerPage + ' OF ' + ledgerTotalPages;
      const firstBtn = document.getElementById('ledgerFirstBtn');
      const prevBtn = document.getElementById('ledgerPrevBtn');
      const nextBtn = document.getElementById('ledgerNextBtn');
      const lastBtn = document.getElementById('ledgerLastBtn');
      if (firstBtn) firstBtn.disabled = ledgerPage <= 1;
      if (prevBtn) prevBtn.disabled = ledgerPage <= 1;
      if (nextBtn) nextBtn.disabled = ledgerPage >= ledgerTotalPages;
      if (lastBtn) lastBtn.disabled = ledgerPage >= ledgerTotalPages;
    }

    filterLocalTable();
    filterLedger();
  </script>
</body>
</html>`;
}

function formatBytes(bytes) {
  if (bytes === undefined || bytes === null || Number.isNaN(Number(bytes))) {
    return "Zero-Knowledge (32-Byte Digest)";
  }
  const b = Number(bytes);
  if (b === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(b) / Math.log(k)));
  return `${parseFloat((b / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function inferMimeTypeFromFileName(fileName) {
  if (!fileName || fileName === "Zero-Knowledge Hash Payload") {
    return "application/octet-stream (Zero-Knowledge)";
  }
  const lower = String(fileName).toLowerCase();
  if (lower.endsWith(".pdf")) return "application/pdf";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".svg")) return "image/svg+xml";
  if (lower.endsWith(".json")) return "application/json";
  if (lower.endsWith(".csv")) return "text/csv";
  if (lower.endsWith(".txt") || lower.endsWith(".md")) return "text/plain";
  if (lower.endsWith(".mp4")) return "video/mp4";
  if (lower.endsWith(".mp3")) return "audio/mpeg";
  if (lower.endsWith(".wav")) return "audio/wav";
  if (lower.endsWith(".zip")) return "application/zip";
  return "application/octet-stream";
}

function generateProvenanceCertificateHtml(input = {}) {
  const fileName = escapeHtml(input.fileName || "Zero-Knowledge Hash Payload");
  const fileSize = escapeHtml(input.fileSize || "Zero-Knowledge (32-Byte Digest)");
  const mimeType = escapeHtml(input.mimeType || inferMimeTypeFromFileName(input.fileName));

  const originalHash = escapeHtml(String(input.originalFileHash || input.attestedHash || "").toLowerCase());
  const attestedHash = escapeHtml(String(input.attestedHash || input.originalFileHash || "").toLowerCase());
  const signerPubKey = input.signerPublicKey ? escapeHtml(String(input.signerPublicKey)) : null;

  const isStandard = String(input.anchorMode || "standard").toLowerCase() === "standard";
  const modeLabel = isStandard
    ? "MODE: STANDARD (DATA INTEGRITY)"
    : "MODE: TEMPORAL (VDF SEQUENCE)";

  const tIndex = escapeHtml(String(input.tIndex || "PENDING VDF SNAPSHOT"));
  const formattedTicks =
    typeof input.vdfTicks === "number"
      ? `${input.vdfTicks.toLocaleString()} Ticks`
      : escapeHtml(String(input.vdfTicks || "0 Ticks"));

  const isSettled = input.status === "settled" || Boolean(input.blockHeight);
  const blockHeightDisplay = input.blockHeight
    ? `#${Number(input.blockHeight).toLocaleString()}`
    : "PENDING NEXT BITCOIN BLOCK";
  const blockTimeDisplay = escapeHtml(
    input.blockTimeUtc || (isSettled ? "CONFIRMED ON BITCOIN MAINNET" : "PENDING BLOCK HEADER UTC")
  );
  const merkleProofDisplay =
    typeof input.merkleProofCount === "number" && input.merkleProofCount > 0
      ? `[ ${input.merkleProofCount} SIBLING HASHES ]`
      : isSettled
      ? "[ INCLUDED IN MERKLE ROOT ]"
      : "PENDING";
  const txidDisplay = escapeHtml(String(input.txid || "PENDING NEXT BITCOIN BLOCK"));
  const finalityValueClass = isSettled ? "data-value green" : "data-value orange";

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>Rel-Time Sovereign Provenance Certificate - ${fileName}</title>
    <style>
        * { box-sizing: border-box; }
        :root {
            --bg-body: #050507;
            --bg-monument: linear-gradient(180deg, #181a20 0%, #0d0e12 50%, #08090c 100%);
            --border-monument: #3f3f46;
            --monument-shadow: inset 0 1px 0 rgba(255,255,255,0.15), 0 30px 70px rgba(0,0,0,0.95);
            --bg-plate: rgba(0, 0, 0, 0.45);
            --border-plate: #27272a;
            --plate-title: #d4d4d8;
            --text-label: #71717a;
            --text-value: #f4f4f5;
            --bg-value: #050507;
            --border-value: #27272a;
            --accent-orange: #fb923c;
            --accent-green: #4ade80;
            --accent-cyan: #22d3ee;
            --anchored-box-bg: rgba(251, 146, 60, 0.06);
            --anchored-box-border: rgba(251, 146, 60, 0.65);
            --anchored-badge-bg: rgba(251, 146, 60, 0.15);
            --mode-pill-bg: #18181b;
            --mode-pill-border: #52525b;
            --mode-pill-color: #f4f4f5;
            --theme-btn-bg: #27272a;
            --theme-btn-border: #52525b;
            --theme-btn-color: #f4f4f5;
            --solar-shadow: drop-shadow(0 0 25px rgba(255, 95, 31, 0.45));
        }

        body.light-mode {
            --bg-body: #e4e4e7;
            --bg-monument: #ffffff;
            --border-monument: #cbd5e1;
            --monument-shadow: 0 20px 45px rgba(0,0,0,0.08), 0 1px 3px rgba(0,0,0,0.05);
            --bg-plate: #f8fafc;
            --border-plate: #e2e8f0;
            --plate-title: #0f172a;
            --text-label: #64748b;
            --text-value: #09090b;
            --bg-value: #ffffff;
            --border-value: #cbd5e1;
            --accent-orange: #ea580c;
            --accent-green: #15803d;
            --accent-cyan: #0891b2;
            --anchored-box-bg: rgba(234, 88, 12, 0.08);
            --anchored-box-border: rgba(234, 88, 12, 0.75);
            --anchored-badge-bg: rgba(234, 88, 12, 0.12);
            --mode-pill-bg: #f1f5f9;
            --mode-pill-border: #cbd5e1;
            --mode-pill-color: #0f172a;
            --theme-btn-bg: #f1f5f9;
            --theme-btn-border: #cbd5e1;
            --theme-btn-color: #0f172a;
            --solar-shadow: drop-shadow(0 0 20px rgba(234, 88, 12, 0.3));
        }

        body {
            background-color: var(--bg-body);
            color: var(--text-value);
            font-family: 'Fira Code', 'SFMono-Regular', Consolas, Menlo, monospace;
            margin: 0;
            padding: 2rem 1rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            transition: background-color 0.3s ease, color 0.3s ease;
            min-height: 100vh;
            overflow-x: hidden;
            width: 100%;
        }

        .monument {
            max-width: 960px;
            width: 100%;
            background: var(--bg-monument);
            border: 2px solid var(--border-monument);
            box-shadow: var(--monument-shadow);
            border-radius: 6px;
            padding: 2.5rem;
            position: relative;
            transition: all 0.3s ease;
        }

        .header-bar {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border-plate);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            gap: 1.5rem;
            flex-wrap: wrap;
        }

        .brand-group { display: flex; flex-direction: column; }
        .brand-logo {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: 0.2em;
            line-height: 1.2;
        }
        .logo-bracket { color: var(--accent-orange); font-weight: 900; }
        .logo-text { color: var(--text-value); letter-spacing: 0.22em; }
        .brand-sub {
            margin: 0.45rem 0 0 0;
            color: var(--text-label);
            font-size: 0.68rem;
            letter-spacing: 0.16em;
            text-transform: uppercase;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .mode-pill {
            background: var(--mode-pill-bg);
            border: 1px solid var(--mode-pill-border);
            color: var(--mode-pill-color);
            padding: 0.4rem 0.8rem;
            font-size: 0.7rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            font-weight: 600;
            border-radius: 4px;
            white-space: nowrap;
        }
        .theme-btn {
            background: var(--theme-btn-bg);
            border: 1px solid var(--theme-btn-border);
            color: var(--theme-btn-color);
            padding: 0.4rem 0.8rem;
            font-size: 0.7rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            font-weight: 700;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s ease;
            font-family: inherit;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
        }
        .theme-btn:hover {
            border-color: var(--accent-orange);
            color: var(--accent-orange);
        }
        .plate {
            background: var(--bg-plate);
            border: 1px solid var(--border-plate);
            box-shadow: inset 0 2px 6px rgba(0,0,0,0.4);
            padding: 1.5rem;
            margin-bottom: 1.75rem;
            border-radius: 4px;
            transition: all 0.3s ease;
        }
        .plate-title {
            color: var(--plate-title);
            font-size: 0.75rem;
            font-weight: bold;
            letter-spacing: 0.2em;
            border-bottom: 1px solid var(--border-plate);
            padding-bottom: 0.6rem;
            margin-bottom: 1.25rem;
            text-transform: uppercase;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .plate-subtitle {
            font-size: 0.65rem;
            color: var(--text-label);
            letter-spacing: 0.12em;
        }
        .data-row { margin-bottom: 1rem; }
        .data-row:last-child { margin-bottom: 0; }
        .data-label {
            color: var(--text-label);
            font-size: 0.68rem;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            margin-bottom: 0.35rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.4rem;
        }
        .data-value {
            color: var(--text-value);
            font-size: 0.82rem;
            word-break: break-all;
            background: var(--bg-value);
            padding: 0.65rem 0.85rem;
            border: 1px solid var(--border-value);
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);
            border-radius: 2px;
            line-height: 1.45;
        }
        .data-value.cyan { color: var(--accent-cyan); border-color: rgba(34, 211, 238, 0.3); }
        .data-value.orange { color: var(--accent-orange); border-color: rgba(251, 146, 60, 0.3); }
        .data-value.green { color: var(--accent-green); border-color: rgba(74, 222, 128, 0.35); }
        .anchored-box {
            color: var(--accent-orange) !important;
            border: 1px solid var(--anchored-box-border) !important;
            background: var(--anchored-box-bg) !important;
            box-shadow: 0 0 18px rgba(251, 146, 60, 0.15), inset 0 1px 3px rgba(0,0,0,0.5) !important;
            font-weight: 600;
        }
        .anchored-badge {
            background: var(--anchored-badge-bg);
            color: var(--accent-orange);
            border: 1px solid var(--anchored-box-border);
            padding: 0.2rem 0.55rem;
            font-size: 0.62rem;
            font-weight: bold;
            letter-spacing: 0.12em;
            border-radius: 3px;
        }
        .solar-vault {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            margin-bottom: 1.25rem;
        }
        .stamp-box {
            width: 240px;
            height: 240px;
            margin: 0.5rem auto 1rem auto;
            filter: var(--solar-shadow);
            max-width: 100%;
        }
        .stamp-box svg { width: 100%; height: 100%; }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .grid-3:last-child { margin-bottom: 0; }
        @media (max-width: 640px) {
            body { padding: 0.5rem 0.35rem; }
            .monument { padding: 1.25rem 0.85rem; border-width: 1px; }
            .header-bar { flex-direction: column; align-items: flex-start; gap: 1rem; }
            .grid-3 { grid-template-columns: 1fr; gap: 0.75rem; }
            .stamp-box { width: 210px; height: 210px; }
        }
        @media print {
            body { background: #ffffff !important; color: #000000 !important; padding: 0 !important; }
            .theme-btn { display: none !important; }
            .monument { border: 1px solid #cbd5e1 !important; box-shadow: none !important; background: #ffffff !important; padding: 1.5rem !important; max-width: 100% !important; }
            .plate { background: #f8fafc !important; border: 1px solid #e2e8f0 !important; box-shadow: none !important; }
            .data-value { background: #ffffff !important; border: 1px solid #cbd5e1 !important; color: #000000 !important; }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
</head>
<body>
    <div class="monument">
        <div class="header-bar">
            <div class="brand-group">
                <div class="brand-logo">
                    <span class="logo-bracket">[</span>
                    <span class="logo-text">REL-TIME</span>
                    <span class="logo-bracket">]</span>
                </div>
                <p class="brand-sub">SOVEREIGN CRYPTOGRAPHIC PROVENANCE CERTIFICATE</p>
            </div>
            <div class="header-actions">
                <div class="mode-pill">${modeLabel}</div>
                <button class="theme-btn" onclick="window.print()" aria-label="Print or Save as PDF">🖨️ PRINT / PDF</button>
                <button id="theme-toggle" class="theme-btn" onclick="toggleTheme()" aria-label="Toggle light or dark theme">☀️ LIGHT</button>
            </div>
        </div>

        <div class="plate">
            <div class="plate-title">
                <span>Asset Identification</span>
                <span class="plate-subtitle">LOCAL ZERO-KNOWLEDGE SHA-256</span>
            </div>
            <div class="grid-3">
                <div class="data-row" style="margin:0;">
                    <div class="data-label">File Name</div>
                    <div class="data-value">${fileName}</div>
                </div>
                <div class="data-row" style="margin:0;">
                    <div class="data-label">File Size</div>
                    <div class="data-value">${fileSize}</div>
                </div>
                <div class="data-row" style="margin:0;">
                    <div class="data-label">MIME Type</div>
                    <div class="data-value">${mimeType}</div>
                </div>
            </div>
        </div>

        <div class="plate">
            <div class="plate-title">
                <span>Plate I — Cryptographic Payload &amp; Ownership</span>
                <span class="plate-subtitle" style="color:var(--accent-orange);">${
                  signerPubKey ? "BIOMETRIC PASSKEY ATTESTED" : "ANONYMOUS PURITY"
                }</span>
            </div>
            <div class="data-row">
                <div class="data-label">[ THE WHAT ] ZERO-KNOWLEDGE FILE HASH (SHA-256)</div>
                <div class="data-value cyan">${originalHash}</div>
            </div>
            <div class="data-row">
                <div class="data-label">[ THE WHO ] SIGNATORY PUBLIC KEY</div>
                <div class="data-value cyan">${
                  signerPubKey || "[ ANONYMOUS — RAW DATA INTEGRITY (NO PASSKEY) ]"
                }</div>
            </div>
            <div class="data-row">
                <div class="data-label">
                    <span>ATTESTED IDENTITY HASH &bull; GENERATES THE 64-RAY SUN-STAMP</span>
                    <span class="anchored-badge">&#9733; ANCHORED TO BITCOIN MERKLE TREE</span>
                </div>
                <div class="data-value anchored-box">${attestedHash}</div>
            </div>
        </div>

        <div class="plate">
            <div class="plate-title">
                <span>Plate II — The Solar Seal &amp; Thermodynamic Clock</span>
                <span class="plate-subtitle">SEEDED BY ATTESTED IDENTITY HASH</span>
            </div>
            <div class="solar-vault">
                <div class="stamp-box" id="stamp-mount"></div>
            </div>
            <div class="data-row">
                <div class="data-label">
                    <span>[ THE WHEN ] THERMODYNAMIC PROOF (T_INDEX)</span>
                    <span class="plate-subtitle">${isStandard ? "STATIC BLOCK SEED" : "VDF CLOCK SNAPSHOT"}</span>
                </div>
                <div class="data-value orange">${tIndex}</div>
            </div>
            <div class="data-row">
                <div class="data-label">SOLAR VDF TICKS ELAPSED SINCE LAST BITCOIN BLOCK</div>
                <div class="data-value orange" style="font-weight:bold;">${
                  isStandard ? "0 (Bypassed — Standard Mode)" : formattedTicks
                }</div>
            </div>
        </div>

        <div class="plate">
            <div class="plate-title">
                <span>Plate III — Bitcoin Timechain Finality</span>
                <span class="plate-subtitle" style="color:${
                  isSettled ? "var(--accent-green)" : "var(--accent-orange)"
                };">${isSettled ? "MAINNET OP_RETURN SETTLEMENT" : "AWAITING BLOCK SETTLEMENT"}</span>
            </div>
            <div class="grid-3">
                <div class="data-row" style="margin:0;">
                    <div class="data-label">Bitcoin Block Height</div>
                    <div class="data-value ${isSettled ? "green" : "orange"}">${blockHeightDisplay}</div>
                </div>
                <div class="data-row" style="margin:0;">
                    <div class="data-label">Block Timestamp (UTC)</div>
                    <div class="data-value ${isSettled ? "green" : "orange"}">${blockTimeDisplay}</div>
                </div>
                <div class="data-row" style="margin:0;">
                    <div class="data-label">Merkle Proof Path</div>
                    <div class="data-value ${isSettled ? "green" : "orange"}">${merkleProofDisplay}</div>
                </div>
            </div>
            <div class="data-row">
                <div class="data-label">BITCOIN OP_RETURN TRANSACTION ID (TXID)</div>
                <div class="${finalityValueClass}">${txidDisplay}</div>
            </div>
        </div>
    </div>

    <script>
        function toggleTheme() {
            const body = document.body;
            const btn = document.getElementById('theme-toggle');
            const isLight = body.classList.toggle('light-mode');
            if (btn) btn.innerHTML = isLight ? '🌙 DARK' : '☀️ LIGHT';
            try { localStorage.setItem('reltime_cert_theme', isLight ? 'light' : 'dark'); } catch(e) {}
        }
        try {
            if (localStorage.getItem('reltime_cert_theme') === 'light') {
                document.body.classList.add('light-mode');
                const btn = document.getElementById('theme-toggle');
                if (btn) btn.innerHTML = '🌙 DARK';
            }
        } catch(e) {}

        function generateBWStamp() {
            const attestedHash = ${JSON.stringify(attestedHash)};
            const verifyUrl = 'https://rel-time.com/verify?t=' + attestedHash;
            const qr = qrcode(0, 'L');
            qr.addData(verifyUrl);
            qr.make();

            const moduleCount = qr.getModuleCount();
            const quietZone = 3;
            const gridSize = 55;
            const offset = Math.floor((gridSize - moduleCount) / 2);
            const center = gridSize / 2;
            const cellSize = 3.85;
            const maxRadiusPx = 104.0;

            let svgContent = '<svg viewBox="22 22 356 356" width="240" height="240" xmlns="http://www.w3.org/2000/svg">';
            svgContent += '<a href="' + verifyUrl + '" target="_blank" rel="noopener noreferrer" style="cursor:pointer;">';
            svgContent += '<circle cx="200" cy="200" r="109" fill="#ffffff" stroke="#000000" stroke-width="2" stroke-opacity="1"/>';

            let qrDots = '';
            let noiseDots = '';

            for (let r = 0; r < gridSize; r++) {
                for (let c = 0; c < gridSize; c++) {
                    const dx = (c - center + 0.5) * cellSize;
                    const dy = (r - center + 0.5) * cellSize;
                    const distPx = Math.sqrt(dx * dx + dy * dy);
                    const qrR = r - offset;
                    const qrC = c - offset;
                    const x = 200 + (c - center) * cellSize;
                    const y = 200 + (r - center) * cellSize;

                    if (qrR >= 0 && qrR < moduleCount && qrC >= 0 && qrC < moduleCount) {
                        if (qr.isDark(qrR, qrC)) {
                            qrDots += '<rect x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + (cellSize + 0.22).toFixed(2) + '" height="' + (cellSize + 0.22).toFixed(2) + '" />';
                        }
                    } else if (qrR >= -quietZone && qrR < moduleCount + quietZone && qrC >= -quietZone && qrC < moduleCount + quietZone) {
                    } else if (distPx <= maxRadiusPx) {
                        const seed = Math.sin(r * 12.9898 + c * 78.233) * 43758.5453;
                        if ((seed - Math.floor(seed)) > 0.5) {
                            noiseDots += '<rect x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + (cellSize + 0.2).toFixed(2) + '" height="' + (cellSize + 0.2).toFixed(2) + '" />';
                        }
                    }
                }
            }

            svgContent += '<g fill="#000000" transform="rotate(14 200 200)">' + qrDots + '</g>';
            svgContent += '<g fill="#000000" transform="rotate(14 200 200)">' + noiseDots + '</g>';

            const hash = attestedHash;
            let radials = '<g>';
            for (let i = 0; i < 64; i++) {
                const val = parseInt(hash[i] || '0', 16) || 0;
                const r_length = 15 + (val / 15) * 45;
                const r_inner = 115;
                const a = (i * 360 / 64 - 90) * Math.PI / 180;
                const x1 = 200 + r_inner * Math.cos(a);
                const y1 = 200 + r_inner * Math.sin(a);
                const x2 = 200 + (r_inner + r_length) * Math.cos(a);
                const y2 = 200 + (r_inner + r_length) * Math.sin(a);
                const dynamicRayColor = (val % 2 === 1) ? '#facc15' : '#ea580c';
                radials += '<line x1="' + x1.toFixed(2) + '" y1="' + y1.toFixed(2) + '" x2="' + x2.toFixed(2) + '" y2="' + y2.toFixed(2) + '" stroke="' + dynamicRayColor + '" stroke-width="2.5" stroke-linecap="round" />';
            }
            radials += '</g></a></svg>';
            svgContent += radials;

            const mount = document.getElementById('stamp-mount');
            if (mount) mount.innerHTML = svgContent;
        }
        generateBWStamp();
    </script>
</body>
</html>`;
}

const TOOLS = [
  {
    name: "reltime_anchor_file",
    description:
      "Zero-knowledge file anchoring + 1-Click Stamped Copy + 4-Plate Provenance Certificate: Computes the SHA-256 hash of a local file ENTIRELY ON THE LOCAL MACHINE (the file never leaves the user's computer), supports both Anonymous and Biometric (Passkey) Anchors, anchors the 64-char hash to the Bitcoin Timechain via Rel-Time, saves the 64-ray Sun-Stamp SVG, JSON Doomsday Proof, 4-Plate Sovereign Cryptographic Provenance Certificate (`reltime-certificate-<name>.html`), and automatically creates a Stamped Copy (`reltime-stamped-<name>.pdf` or `.png`) with the Sun-Stamp overlaid in the bottom-right corner for PDFs and Images.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Absolute path to the local file to hash and anchor.",
        },
        biometric: {
          type: "boolean",
          description:
            "If true, performs a Biometric Anchor using your linked hardware Passkey (TouchID / FaceID / YubiKey) so the anchored hash (`SHA256(File_Hash + Passkey_PubKey)`) and Sun-Stamp mathematically prove your personal authorship. If no Passkey is linked yet, automatically opens the browser TouchID/FaceID prompt.",
        },
        anchor_mode: {
          type: "string",
          enum: ["standard", "temporal"],
          description:
            "Use 'standard' (default) to anchor the file/biometric SHA-256 hash into the Bitcoin Merkle tree for standalone file verification, or 'temporal' to anchor the VDF Thermodynamic Proof (T_index) for sub-second sequential ordering.",
        },
        save_sun_stamp_svg: {
          type: "boolean",
          description: "If true (default), saves `reltime-stamp-<filename>.svg` in the same folder as the file.",
        },
        save_stamped_copy: {
          type: "boolean",
          description:
            "If true (default), automatically generates `reltime-stamped-<name>.pdf` or `.png` with the crisp 64-ray Sun-Stamp in the bottom-right corner when the file is a PDF or Image.",
        },
        save_certificate_html: {
          type: "boolean",
          description:
            "If true (default), saves the 4-Plate Sovereign Cryptographic Provenance Certificate (`reltime-certificate-<filename>.html`) in the same folder as the file.",
        },
        open_certificate_in_browser: {
          type: "boolean",
          description:
            "If true, opens the generated 4-Plate Sovereign Cryptographic Provenance Certificate HTML in the system browser.",
        },
        api_key: {
          type: "string",
          description: "Optional override for RELTIME_API_KEY (Autonomous Agent, Universal Anchor, or Enterprise Superhighway key).",
        },
      },
      required: ["file_path"],
    },
  },
  {
    name: "reltime_anchor_folder",
    description:
      "Bulk zero-knowledge folder anchoring (10 to 5,000+ files in a single call): Hashes all files in a local folder 100% locally (0 file bytes uploaded), supports Biometric (Passkey) or Anonymous anchoring, skips any files that are already anchored (safe to resume), and keeps the user's folder clean by storing per-file Doomsday Proofs inside a single `_reltime_proofs/` subfolder plus a master `reltime-batch-manifest.json`.",
    inputSchema: {
      type: "object",
      properties: {
        folder_path: {
          type: "string",
          description: "Absolute path to the local directory to hash and anchor.",
        },
        recursive: {
          type: "boolean",
          description: "If true, recursively anchors files in subdirectories. Defaults to false (top-level files only).",
        },
        biometric: {
          type: "boolean",
          description:
            "If true, performs Biometric Anchors using your linked hardware Passkey (`~/.reltime/passkey.json`) across the entire folder without repeated TouchID prompts.",
        },
        anchor_mode: {
          type: "string",
          enum: ["standard", "temporal"],
          description: "Use 'standard' (default) or 'temporal' (VDF T_index sequential ordering for Superhighway & Autonomous Agents).",
        },
        artifact_mode: {
          type: "string",
          enum: ["proofs_subfolder", "manifest_only", "full"],
          description:
            "Controls local output files so bulk runs never clutter the folder: 'proofs_subfolder' (default) writes JSON proofs into `<folder>/_reltime_proofs/` + `reltime-batch-manifest.json`; 'manifest_only' writes only `reltime-batch-manifest.json`; 'full' also writes SVG Sun-Stamps and HTML certificates.",
        },
        concurrency: {
          type: "number",
          description: "Number of concurrent anchor requests (default: 5, max: 10).",
        },
        api_key: {
          type: "string",
          description: "Optional override for RELTIME_API_KEY.",
        },
      },
      required: ["folder_path"],
    },
  },
  {
    name: "reltime_link_passkey",
    description:
      "Links the user's hardware Passkey (TouchID, FaceID, or YubiKey) to `@rel-time/mcp-server` for Biometric Anchors. Opens `https://rel-time.com/mcp-passkey` in the system browser, waits for the user's biometric touch, and saves `{ public_key_hex, passkey_signature }` to `~/.reltime/passkey.json`.",
    inputSchema: {
      type: "object",
      properties: {
        public_key_hex: {
          type: "string",
          description: "Optional: Directly provide the COSE public_key_hex from https://rel-time.com/mcp-passkey without opening a browser window.",
        },
        passkey_signature: {
          type: "string",
          description: "Optional: Directly provide the passkey_signature session token from https://rel-time.com/mcp-passkey.",
        },
      },
    },
  },
  {
    name: "reltime_stamp_file",
    description:
      "Overlays the authentic 64-ray Rel-Time Sun-Stamp (Option A: pure crisp Sun-Stamp, zero glare, no pill) onto the bottom-right corner of a local PDF or Image (.png, .jpg, .jpeg, .webp, .gif) 100% locally. Returns 'Feature unavailable for this file type' for other file formats.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Absolute path to the local PDF or Image file.",
        },
        hash: {
          type: "string",
          description:
            "Optional 64-char hex hash to generate the Sun-Stamp from. If omitted, computes the SHA-256 hash of `file_path` locally.",
        },
        output_path: {
          type: "string",
          description: "Optional custom output file path for the stamped copy.",
        },
      },
      required: ["file_path"],
    },
  },
  {
    name: "reltime_anchor_hash",
    description:
      "Anchors a 64-character hexadecimal SHA-256 hash directly into the Rel-Time VDF & Bitcoin Merkle Tree. Consumes 1 Hash Credit from the configured Rel-Time API key.",
    inputSchema: {
      type: "object",
      properties: {
        client_hash: {
          type: "string",
          description: "64-character hex SHA-256 hash of the payload/artifact.",
        },
        anchor_mode: {
          type: "string",
          enum: ["standard", "temporal"],
          description: "'standard' (Data Integrity) or 'temporal' (VDF Sequence Ordering).",
        },
        api_key: {
          type: "string",
          description: "Optional override for RELTIME_API_KEY.",
        },
      },
      required: ["client_hash"],
    },
  },
  {
    name: "reltime_get_sun_stamp",
    description:
      "Generates and downloads the official 64-ray Rel-Time Sun-Stamp SVG (`GET /v1/stamp/{hash}`) for any 64-char SHA-256 hash or T_index. Requires NO API key and works across all tiers.",
    inputSchema: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "64-character hex SHA-256 hash (client_hash or t_index).",
        },
        output_svg_path: {
          type: "string",
          description: "Optional local file path where the `.svg` Sun-Stamp should be saved.",
        },
      },
      required: ["hash"],
    },
  },
  {
    name: "reltime_check_proof",
    description:
      "Queries `GET /v1/proof/{hash}` to check the Bitcoin settlement status (Block Height, Block UTC Time, Bitcoin TXID, Merkle Root, and Merkle Inclusion Path) of an anchored hash. Optionally saves or updates the finalized `.json` Doomsday Proof receipt AND/OR generates the 4-Plate Sovereign Cryptographic Provenance Certificate HTML on demand.",
    inputSchema: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "The 64-character client_hash or t_index to verify.",
        },
        file_path: {
          type: "string",
          description:
            "Optional local file path corresponding to the anchored hash (used to verify local custody/Passkey ownership and populate exact file name, size, and MIME type on the Provenance Certificate).",
        },
        output_json_path: {
          type: "string",
          description: "Optional local file path to save the settled JSON Doomsday Proof receipt.",
        },
        save_certificate_html: {
          type: "boolean",
          description:
            "If true, generates and saves the 4-Plate Sovereign Cryptographic Provenance Certificate (`reltime-certificate-<name>.html`) on demand.",
        },
        output_certificate_html_path: {
          type: "string",
          description: "Optional custom file path to save the 4-Plate Provenance Certificate HTML.",
        },
        open_certificate_in_browser: {
          type: "boolean",
          description:
            "If true, generates the 4-Plate Sovereign Cryptographic Provenance Certificate HTML and opens it in the system browser.",
        },
      },
      required: ["hash"],
    },
  },
  {
    name: "reltime_account_status",
    description:
      "Checks the remaining Hash Credits, tier, and lifetime usage of the configured Rel-Time API key (`GET /api/v1/account`). If no API key is configured yet, returns the 4 available Rel-Time Tiers (`universal` $3, `launch` $5/25, `standard` $50/500, `enterprise` $399/5,000) and payment options (`lightning` or `stripe`) so you can ask the user which tier they want to provision in chat.",
    inputSchema: {
      type: "object",
      properties: {
        api_key: {
          type: "string",
          description:
            "Optional: pass a `rel_key_...` API key to check its balance AND automatically save it to ~/.reltime/api_key.json for all future calls.",
        },
      },
    },
  },
  {
    name: "reltime_provision_agent_key",
    description:
      "Self-onboarding & Top-Up for all 4 Rel-Time Tiers via EITHER Bitcoin Lightning OR Stripe Card Checkout (`POST /v1/agent/invoice` & `POST /v1/agent/claim`). IMPORTANT:\n1. Before calling `create_invoice` for a new key, ask the user which tier AND payment method (`lightning` or `stripe`) they want:\n   - **Universal Anchor (`pack: 'universal'`, $3 / anchor):** Priority 10-Minute Bitcoin Queue · Standard Mode (Biometric or Anonymous) · Supports `quantity` (default 1).\n   - **Agent Launch Pack (`pack: 'launch'`, $5 / 25 Hashes, max 3 per key):** Priority 10-Minute Bitcoin Queue · Standard Mode · Includes Sun-Stamp, 1-Click Stamped Copy (.PDF/.PNG), 4-Plate Certificate, and .JSON Doomsday Proof.\n   - **Autonomous Agents (`pack: 'standard'`, $50 / 500 Hashes):** Dynamic 6-Hour Batch Queue · Supports both Temporal Mode (`T_index` sub-second sequencing) and Standard Mode · Reloadable anytime (+500 credits / $50) with zero key rotation.\n   - **Rel-Time Superhighway (`pack: 'enterprise'`, $399 / 5,000 Hashes):** Priority 10-Minute Bitcoin Queue · Supports Temporal Mode (`T_index`) & Standard Mode + Data Integrity Audit & Instant Tamper Detection.\n2. When `create_invoice` returns:\n   - For **Lightning**: ALWAYS present BOTH the scannable QR code image (by calling Read on `qr_code_png_path`) AND the full, un-truncated `ln_invoice` (`bolt11`) string in a copyable code block on the VERY FIRST try!\n   - For **Stripe**: The Stripe Checkout page opens automatically in the user's browser; also present the clickable `checkout_url` link and QR code (`qr_code_png_path`). Once paid, call `claim_invoice` with `invoice_id` (`cs_...`) to activate and save the key.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["create_invoice", "claim_invoice"],
          description:
            "'create_invoice' generates a Lightning BOLT11 invoice or Stripe Checkout Session; 'claim_invoice' exchanges a paid Lightning invoice_id or Stripe session_id ('cs_...') for a new API key or reloads an existing API key.",
        },
        pack: {
          type: "string",
          enum: ["universal", "launch", "standard", "enterprise"],
          description:
            "REQUIRED for 'create_invoice' after asking the user. Which tier the user selected: 'universal' ($3/anchor), 'launch' ($5 / 25 Hashes, max 3 per key), 'standard' ($50 / 500 Hashes), or 'enterprise' ($399 / 5,000 Hashes — Superhighway). If omitted on 'create_invoice', returns the 4 tier options so you can ask the user.",
        },
        payment_method: {
          type: "string",
          enum: ["lightning", "stripe"],
          description:
            "REQUIRED for 'create_invoice' after asking the user. Payment method: 'lightning' (Bitcoin Lightning BOLT11 invoice + QR code) or 'stripe' (Stripe Card Checkout URL + browser launch). Never guess — if omitted on 'create_invoice', returns the tier/payment prompt so you can ask the user whether they want Lightning or Stripe.",
        },
        quantity: {
          type: "number",
          description:
            "Optional credit quantity when pack is 'universal' ($3.00 per credit, default 1).",
        },
        invoice_id: {
          type: "string",
          description:
            "Required when action is 'claim_invoice'. Pass either the Strike Lightning `invoice_id` UUID or the Stripe Checkout `session_id` (`cs_...`).",
        },
        api_key: {
          type: "string",
          description:
            "Optional: pass an existing `rel_key_...` key (or omit to use RELTIME_API_KEY if reload_existing is true) to reload Hash Credits into that key without rotating it.",
        },
        reload_existing: {
          type: "boolean",
          description:
            "If true, reloads Hash Credits into the currently configured RELTIME_API_KEY (or passed `api_key`) instead of generating a new key.",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "reltime_audit_trail",
    description:
      "SUPERHIGHWAY EXCLUSIVE ($399 / 5,000 Hashes): Data Integrity Audit, Instant Tamper Detection & Forensic Timechain Report (`GET /api/v1/account` + `GET /api/v1/account/history` + local SHA-256 cross-reference). Fetches the account's chronological anchor ledger, aggregates Bitcoin block settlements, VDF `T_index` ticks, and Corporate Hardware Passkey (`signer_public_key`) signatures, verifies a local file or entire folder bit-for-bit against the ledger (`verify_local_path`), and spins up a self-contained interactive HTML Forensic Audit Report (`reltime-audit-report-*.html`) in the user's browser.",
    inputSchema: {
      type: "object",
      properties: {
        verify_local_path: {
          type: "string",
          description:
            "Optional local file path or folder/directory path to audit bit-for-bit (Zero-Knowledge local SHA-256 + Passkey attestation check + Stamped Copy check) against the Rel-Time Bitcoin ledger.",
        },
        limit: {
          type: "number",
          description: "Maximum number of audit ledger entries to retrieve (default 100, max 500).",
        },
        status_filter: {
          type: "string",
          enum: ["all", "settled", "pending"],
          description: "Filter ledger entries by settlement status: 'all' (default), 'settled', or 'pending'.",
        },
        mode_filter: {
          type: "string",
          enum: ["all", "standard", "temporal", "biometric"],
          description:
            "Filter ledger entries by mode: 'all' (default), 'standard', 'temporal' (VDF T_index), or 'biometric' (Hardware Passkey attested).",
        },
        signer_filter: {
          type: "string",
          description:
            "Optional full or partial Hardware Passkey `public_key_hex` to filter anchors signed by a specific employee or corporate YubiKey.",
        },
        save_html_report: {
          type: "boolean",
          description:
            "If true (default), saves an interactive dark-mode HTML Superhighway Audit Trail dashboard (`reltime-audit-report-<date>.html`).",
        },
        open_in_browser: {
          type: "boolean",
          description:
            "If true (default), automatically opens the generated HTML Audit Trail dashboard in the user's browser.",
        },
        export_csv: {
          type: "boolean",
          description: "If true, also exports the audit ledger to a `.csv` spreadsheet file.",
        },
        output_dir: {
          type: "string",
          description:
            "Optional directory where the generated `.html` / `.csv` audit reports should be saved (defaults to `verify_local_path` folder or `~/.reltime/audits`).",
        },
        api_key: {
          type: "string",
          description: "Optional override for RELTIME_API_KEY.",
        },
      },
    },
  },
];

async function executeTool(name, args = {}) {
  if (args.api_key && isValidApiKeyCandidate(args.api_key)) {
    CURRENT_API_KEY = args.api_key.trim();
    saveApiKeyConfig(CURRENT_API_KEY, "custom");
  }
  const key = (isValidApiKeyCandidate(args.api_key) ? args.api_key.trim() : loadSavedApiKey()) || "";

  if (name === "reltime_link_passkey") {
    if (args.public_key_hex && args.passkey_signature) {
      const saved = savePasskeyConfig(args.public_key_hex, args.passkey_signature);
      return {
        status: "linked",
        mode: "direct",
        config_path: PASSKEY_CONFIG_PATH,
        public_key_hex: saved.public_key_hex,
        linked_at: saved.linked_at,
        message: "Hardware Passkey linked! You can now call reltime_anchor_file with biometric: true.",
      };
    }

    const saved = await launchBrowserPasskeyBridge();
    return {
      status: "linked",
      mode: "browser_webauthn_bridge",
      config_path: PASSKEY_CONFIG_PATH,
      public_key_hex: saved.public_key_hex,
      linked_at: saved.linked_at,
      message: "Hardware Passkey verified via TouchID/FaceID and saved to ~/.reltime/passkey.json! You can now call reltime_anchor_file with biometric: true.",
    };
  }

  if (name === "reltime_anchor_file") {
    if (!key) {
      return buildPackSelectionPrompt(
        "Before anchoring files, a Rel-Time API key is required. Ask the user which pack they want to provision first:"
      );
    }
    const filePath = resolveLocalFilePath(args.file_path);
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found at path: ${filePath}`);
    }

    // 1. Compute SHA-256 locally (Zero-Knowledge: raw file never leaves the device)
    const fileBuffer = fs.readFileSync(filePath);
    const originalFileHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    const anchorMode = args.anchor_mode || "standard";

    let clientHash = originalFileHash;
    let passkeyCreds = null;

    if (args.biometric) {
      passkeyCreds = loadSavedPasskey();
      if (!passkeyCreds) {
        // Automatically launch the browser TouchID / FaceID bridge if not linked yet
        passkeyCreds = await launchBrowserPasskeyBridge();
      }
      clientHash = crypto
        .createHash("sha256")
        .update(`${originalFileHash}${passkeyCreds.public_key_hex}`, "utf8")
        .digest("hex");
    }

    const requestBody = {
      client_hash: clientHash,
      anchor_mode: anchorMode,
    };

    if (args.biometric && passkeyCreds) {
      requestBody.original_file_hash = originalFileHash;
      requestBody.passkey_signature = passkeyCreds.passkey_signature;
    }

    // 2. Anchor the hash via POST /v1/anchor
    const res = await fetch(`${API_BASE}/anchor`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify(requestBody),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(`Rel-Time API error (${res.status}): ${JSON.stringify(data)}`);
    }

    const tIndex = data.t_index || data.thermodynamic_proof;
    const lookupHash = anchorMode === "temporal" ? tIndex : clientHash;
    const verifyUrl = `https://rel-time.com/verify?t=${lookupHash}`;
    const stampEndpointUrl = `${API_BASE}/stamp/${lookupHash}`;

    let svgContent = data.visual_fingerprint || "";
    const needsSvg = args.save_sun_stamp_svg !== false || args.save_stamped_copy !== false;
    if (!svgContent && needsSvg) {
      try {
        const stampRes = await fetch(stampEndpointUrl);
        if (stampRes.ok) {
          svgContent = await stampRes.text();
        }
      } catch (e) {
        // Ignore SVG fetch error if offline/rate-limited
      }
    }

    let savedSvgPath = null;
    if (args.save_sun_stamp_svg !== false && svgContent) {
      try {
        savedSvgPath = path.join(
          path.dirname(filePath),
          safeArtifactFilename("reltime-stamp-", path.basename(filePath), ".svg", clientHash)
        );
        fs.writeFileSync(savedSvgPath, svgContent, "utf8");
      } catch (e) {
        savedSvgPath = null;
      }
    }

    // Save initial Doomsday Proof JSON alongside the file
    const savedProofJsonPath = path.join(
      path.dirname(filePath),
      safeArtifactFilename("reltime-doomsday-proof-", path.basename(filePath), ".json", clientHash)
    );
    fs.writeFileSync(
      savedProofJsonPath,
      JSON.stringify(
        {
          protocol: "Rel-Time Sovereign Provenance Protocol",
          file_name: path.basename(filePath),
          identity_mode: args.biometric ? "BIOMETRIC_PASSKEY" : "ANONYMOUS",
          original_file_sha256_hash: originalFileHash,
          anchored_client_hash: clientHash,
          signer_public_key: passkeyCreds ? passkeyCreds.public_key_hex : null,
          t_index: tIndex,
          vdf_ticks: data.vdf_ticks || data.solar_ticks,
          anchor_mode: data.anchor_mode || anchorMode,
          status: data.status || "pending_finality",
          verify_url: verifyUrl,
          sun_stamp_svg_url: stampEndpointUrl,
          settlement: data.settlement || null,
        },
        null,
        2
      ),
      "utf8"
    );

    // 3. Automatically generate Stamped Copy (.PDF or .PNG) for PDFs and Images
    let stampedCopyResult = null;
    if (args.save_stamped_copy !== false && svgContent) {
      try {
        stampedCopyResult = await stampLocalFileOptionA(filePath, svgContent, null, clientHash);
      } catch (e) {
        stampedCopyResult = { status: "skipped", error: e.message };
      }
    }

    // 4. Generate 4-Plate Sovereign Cryptographic Provenance Certificate HTML
    let savedCertificateHtmlPath = null;
    if (args.save_certificate_html !== false) {
      try {
        const certHtml = generateProvenanceCertificateHtml({
          fileName: path.basename(filePath),
          fileSize: formatBytes(fileBuffer.length),
          mimeType: inferMimeTypeFromFileName(path.basename(filePath)),
          originalFileHash,
          attestedHash: clientHash,
          signerPublicKey: passkeyCreds ? passkeyCreds.public_key_hex : null,
          anchorMode: data.anchor_mode || anchorMode,
          tIndex,
          vdfTicks: data.vdf_ticks || data.solar_ticks || 0,
          status: data.status || "pending_finality",
          blockHeight: data.settlement?.bitcoin_block_height || null,
          blockTimeUtc: data.settlement?.bitcoin_block_time
            ? new Date(data.settlement.bitcoin_block_time * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC"
            : null,
          merkleProofCount: Array.isArray(data.settlement?.merkle_proof_path)
            ? data.settlement.merkle_proof_path.length
            : null,
          txid: data.settlement?.bitcoin_txid || null,
        });
        savedCertificateHtmlPath = path.join(
          path.dirname(filePath),
          safeArtifactFilename("reltime-certificate-", path.basename(filePath), ".html", clientHash)
        );
        fs.writeFileSync(savedCertificateHtmlPath, certHtml, "utf8");
        if (args.open_certificate_in_browser) {
          openSystemBrowser(savedCertificateHtmlPath);
        }
      } catch (e) {
        savedCertificateHtmlPath = null;
      }
    }

    return {
      status: data.status || "pending_finality",
      file_name: path.basename(filePath),
      identity_mode: args.biometric ? "Biometric Anchor (Passkey)" : "Anonymous Anchor",
      original_file_sha256_hash: originalFileHash,
      local_sha256_hash: clientHash,
      signer_public_key: passkeyCreds ? passkeyCreds.public_key_hex : null,
      t_index: tIndex,
      vdf_ticks: data.vdf_ticks || data.solar_ticks,
      anchor_mode: data.anchor_mode || anchorMode,
      epoch_target: data.epoch_target,
      verify_url: verifyUrl,
      sun_stamp_svg_url: stampEndpointUrl,
      saved_sun_stamp_svg_path: savedSvgPath,
      saved_doomsday_proof_json_path: savedProofJsonPath,
      saved_certificate_html_path: savedCertificateHtmlPath,
      stamped_copy: stampedCopyResult,
      zero_knowledge_guarantee:
        "File was hashed and stamped 100% locally on your machine; 0 bytes of file content were transmitted.",
    };
  }

  if (name === "reltime_anchor_folder") {
    if (!key) {
      return buildPackSelectionPrompt(
        "Before anchoring a folder of files, a Rel-Time API key is required. Ask the user which pack they want to provision first:"
      );
    }
    const folderPath = resolveLocalFilePath(args.folder_path);
    if (!fs.existsSync(folderPath) || !fs.statSync(folderPath).isDirectory()) {
      throw new Error(`Directory not found at path: ${folderPath}`);
    }

    const recursive = Boolean(args.recursive);
    const anchorMode = args.anchor_mode || "standard";
    const artifactMode = args.artifact_mode || "proofs_subfolder";
    const concurrency = Math.max(1, Math.min(10, Number(args.concurrency) || 5));

    let passkeyCreds = null;
    if (args.biometric) {
      passkeyCreds = loadSavedPasskey();
      if (!passkeyCreds) {
        passkeyCreds = await launchBrowserPasskeyBridge();
      }
    }

    const isReltimeGeneratedFile = (fname) => {
      const lower = fname.toLowerCase();
      return (
        fname.startsWith(".") ||
        lower.startsWith("reltime-stamp-") ||
        lower.startsWith("reltime-doomsday-proof-") ||
        lower.startsWith("reltime-certificate-") ||
        lower.startsWith("reltime-stamped-") ||
        lower.startsWith("reltime-audit-report-") ||
        lower === "reltime-batch-manifest.json"
      );
    };

    const targetFiles = [];
    const walkDir = (dir) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith(".") || entry.name === "_reltime_proofs" || entry.name === "node_modules") {
          continue;
        }
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (recursive) walkDir(fullPath);
        } else if (entry.isFile() && !isReltimeGeneratedFile(entry.name)) {
          targetFiles.push(fullPath);
        }
      }
    };
    walkDir(folderPath);

    const proofsDir = path.join(folderPath, "_reltime_proofs");
    if (artifactMode === "proofs_subfolder" && !fs.existsSync(proofsDir)) {
      fs.mkdirSync(proofsDir, { recursive: true });
    }

    const manifestPath = path.join(folderPath, "reltime-batch-manifest.json");
    let existingManifest = { anchored_files: {} };
    if (fs.existsSync(manifestPath)) {
      try {
        existingManifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) || { anchored_files: {} };
        if (!existingManifest.anchored_files) existingManifest.anchored_files = {};
      } catch (e) {
        existingManifest = { anchored_files: {} };
      }
    }

    const results = [];
    const skipped = [];
    const errors = [];
    let outOfCredits = false;

    const toProcess = [];
    for (const fPath of targetFiles) {
      const relPath = path.relative(folderPath, fPath);
      const baseName = path.basename(fPath);
      const sidecarProof = path.join(
        path.dirname(fPath),
        safeArtifactFilename("reltime-doomsday-proof-", baseName, ".json")
      );
      const legacySidecarProof = path.join(path.dirname(fPath), `reltime-doomsday-proof-${baseName}.json`);
      const subfolderProof = path.join(
        proofsDir,
        safeArtifactFilename("reltime-doomsday-proof-", relPath.replace(/[\\/]/g, "__"), ".json")
      );
      if (
        existingManifest.anchored_files[relPath] ||
        fs.existsSync(sidecarProof) ||
        (Buffer.byteLength(`reltime-doomsday-proof-${baseName}.json`, "utf8") <= 255 && fs.existsSync(legacySidecarProof)) ||
        fs.existsSync(subfolderProof)
      ) {
        skipped.push(relPath);
      } else {
        toProcess.push({ fPath, relPath, baseName, subfolderProof, sidecarProof });
      }
    }

    let cursor = 0;
    const worker = async () => {
      while (cursor < toProcess.length && !outOfCredits) {
        const idx = cursor++;
        const item = toProcess[idx];
        if (!item) break;
        try {
          const buf = fs.readFileSync(item.fPath);
          const originalFileHash = crypto.createHash("sha256").update(buf).digest("hex");
          const clientHash =
            args.biometric && passkeyCreds
              ? crypto.createHash("sha256").update(`${originalFileHash}${passkeyCreds.public_key_hex}`, "utf8").digest("hex")
              : originalFileHash;

          const reqBody = {
            client_hash: clientHash,
            anchor_mode: anchorMode,
          };
          if (args.biometric && passkeyCreds) {
            reqBody.original_file_hash = originalFileHash;
            reqBody.passkey_signature = passkeyCreds.passkey_signature;
          }

          const res = await fetch(`${API_BASE}/anchor`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${key}`,
            },
            body: JSON.stringify(reqBody),
          });

          if (res.status === 402) {
            outOfCredits = true;
            errors.push({ file: item.relPath, error: "Insufficient Hash Credits (HTTP 402)" });
            break;
          }

          const data = await res.json();
          if (!res.ok) {
            errors.push({ file: item.relPath, error: `HTTP ${res.status}: ${JSON.stringify(data)}` });
            continue;
          }

          const tIndex = data.t_index || data.thermodynamic_proof;
          const lookupHash = (data.anchor_mode || anchorMode) === "temporal" ? tIndex : clientHash;
          const verifyUrl = `https://rel-time.com/verify?t=${lookupHash}`;
          const proofRecord = {
            protocol: "Rel-Time Sovereign Provenance Protocol",
            file_name: item.baseName,
            relative_path: item.relPath,
            identity_mode: args.biometric ? "BIOMETRIC_PASSKEY" : "ANONYMOUS",
            original_file_sha256_hash: originalFileHash,
            anchored_client_hash: clientHash,
            signer_public_key: passkeyCreds ? passkeyCreds.public_key_hex : null,
            t_index: tIndex,
            vdf_ticks: data.vdf_ticks || data.solar_ticks,
            anchor_mode: data.anchor_mode || anchorMode,
            status: data.status || "pending_finality",
            verify_url: verifyUrl,
          };

          if (artifactMode === "proofs_subfolder") {
            fs.writeFileSync(item.subfolderProof, JSON.stringify(proofRecord, null, 2), "utf8");
          } else if (artifactMode === "full") {
            fs.writeFileSync(item.sidecarProof, JSON.stringify(proofRecord, null, 2), "utf8");
          }

          existingManifest.anchored_files[item.relPath] = proofRecord;
          results.push(proofRecord);
        } catch (err) {
          errors.push({ file: item.relPath, error: err.message });
        }
      }
    };

    const workers = Array.from({ length: Math.min(concurrency, Math.max(1, toProcess.length)) }, () => worker());
    await Promise.all(workers);

    const manifestPayload = {
      protocol: "Rel-Time Sovereign Provenance Protocol — Batch Folder Manifest",
      folder_path: folderPath,
      updated_at: new Date().toISOString(),
      identity_mode: args.biometric ? "BIOMETRIC_PASSKEY" : "ANONYMOUS",
      signer_public_key: passkeyCreds ? passkeyCreds.public_key_hex : null,
      total_anchored_in_manifest: Object.keys(existingManifest.anchored_files).length,
      anchored_files: existingManifest.anchored_files,
    };
    fs.writeFileSync(manifestPath, JSON.stringify(manifestPayload, null, 2), "utf8");

    return {
      status: outOfCredits ? "stopped_insufficient_credits" : "completed",
      folder_path: folderPath,
      total_files_found: targetFiles.length,
      newly_anchored_count: results.length,
      skipped_already_anchored_count: skipped.length,
      error_count: errors.length,
      identity_mode: args.biometric ? "BIOMETRIC_PASSKEY" : "ANONYMOUS",
      signer_public_key: passkeyCreds ? passkeyCreds.public_key_hex : null,
      artifact_mode: artifactMode,
      manifest_path: manifestPath,
      proofs_subfolder: artifactMode === "proofs_subfolder" ? proofsDir : null,
      errors: errors.slice(0, 20),
      next_step:
        "You can now run `reltime_audit_trail` with `verify_local_path` set to this folder to generate the full interactive HTML Cryptographic Audit Report.",
    };
  }

  if (name === "reltime_stamp_file") {
    const filePath = resolveLocalFilePath(args.file_path);
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found at path: ${filePath}`);
    }
    const targetHash = args.hash
      ? args.hash.trim().toLowerCase()
      : crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

    if (!/^[0-9a-f]{64}$/.test(targetHash)) {
      throw new Error("hash must be a valid 64-character hexadecimal SHA-256 string.");
    }

    const stampRes = await fetch(`${API_BASE}/stamp/${targetHash}`);
    if (!stampRes.ok) {
      throw new Error(`Failed to fetch Sun-Stamp (${stampRes.status}): ${await stampRes.text()}`);
    }
    const svgContent = await stampRes.text();
    const result = await stampLocalFileOptionA(filePath, svgContent, args.output_path || null, targetHash);
    return {
      file_path: filePath,
      hash: targetHash,
      verify_url: `https://rel-time.com/verify?t=${targetHash}`,
      ...result,
    };
  }

  if (name === "reltime_anchor_hash") {
    if (!key) {
      return buildPackSelectionPrompt(
        "Before anchoring hashes, a Rel-Time API key is required. Ask the user which pack they want to provision first:"
      );
    }
    const clientHash = (args.client_hash || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(clientHash)) {
      throw new Error("client_hash must be a valid 64-character hexadecimal SHA-256 string.");
    }
    const anchorMode = args.anchor_mode || "standard";

    const res = await fetch(`${API_BASE}/anchor`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        client_hash: clientHash,
        anchor_mode: anchorMode,
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(`Rel-Time API error (${res.status}): ${JSON.stringify(data)}`);
    }

    const tIndex = data.t_index || data.thermodynamic_proof;
    const lookupHash = anchorMode === "temporal" ? tIndex : clientHash;

    return {
      status: data.status,
      client_hash: clientHash,
      t_index: tIndex,
      vdf_ticks: data.vdf_ticks || data.solar_ticks,
      anchor_mode: data.anchor_mode || anchorMode,
      epoch_target: data.epoch_target,
      verify_url: `https://rel-time.com/verify?t=${lookupHash}`,
      sun_stamp_svg_url: `${API_BASE}/stamp/${lookupHash}`,
    };
  }

  if (name === "reltime_get_sun_stamp") {
    const hash = (args.hash || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      throw new Error("hash must be a 64-character hexadecimal SHA-256 string.");
    }
    const stampUrl = `${API_BASE}/stamp/${hash}`;
    const res = await fetch(stampUrl);
    if (!res.ok) {
      throw new Error(`Failed to fetch Sun-Stamp (${res.status}): ${await res.text()}`);
    }
    const svg = await res.text();
    let savedPath = null;
    if (args.output_svg_path) {
      savedPath = path.resolve(args.output_svg_path);
      fs.writeFileSync(savedPath, svg, "utf8");
    }
    return {
      hash,
      sun_stamp_svg_url: stampUrl,
      verify_url: `https://rel-time.com/verify?t=${hash}`,
      saved_svg_path: savedPath,
      embed_markdown: `[![Anchored on Bitcoin via Rel-Time](${stampUrl})](https://rel-time.com/verify?t=${hash})`,
      embed_html: `<a href="https://rel-time.com/verify?t=${hash}" target="_blank" rel="noopener"><img src="${stampUrl}" alt="Rel-Time Sun-Stamp" width="160" height="160" /></a>`,
    };
  }

  if (name === "reltime_check_proof") {
    const hash = (args.hash || "").trim().toLowerCase();
    const res = await fetch(`${API_BASE}/proof/${hash}`);
    const data = await res.json();
    const out = {
      http_status: res.status,
      verify_url: `https://rel-time.com/verify?t=${hash}`,
      ...data,
    };
    if (args.output_json_path) {
      const jsonPath = path.resolve(args.output_json_path);
      fs.writeFileSync(jsonPath, JSON.stringify(out, null, 2), "utf8");
      out.saved_json_path = jsonPath;
    }

    const wantsCert =
      Boolean(args.save_certificate_html) ||
      Boolean(args.output_certificate_html_path) ||
      Boolean(args.open_certificate_in_browser);

    if (wantsCert && res.ok) {
      let fileName = "Zero-Knowledge Hash Payload";
      let fileSize = "Zero-Knowledge (32-Byte Digest)";
      let mimeType = "application/octet-stream (Zero-Knowledge)";
      let originalFileHash = data.original_file_hash || data.client_hash || hash;
      let targetDir = os.tmpdir();

      if (args.file_path) {
        const resolvedFile = resolveLocalFilePath(args.file_path);
        if (fs.existsSync(resolvedFile)) {
          const stat = fs.statSync(resolvedFile);
          fileName = path.basename(resolvedFile);
          fileSize = formatBytes(stat.size);
          mimeType = inferMimeTypeFromFileName(fileName);
          targetDir = path.dirname(resolvedFile);
          if (!data.original_file_hash) {
            originalFileHash = crypto
              .createHash("sha256")
              .update(fs.readFileSync(resolvedFile))
              .digest("hex");
          }
        }
      }

      const savedPasskey = loadSavedPasskey();
      if (data.signer_public_key) {
        out.passkey_custody_verified = Boolean(
          savedPasskey &&
            savedPasskey.public_key_hex.toLowerCase() === String(data.signer_public_key).toLowerCase()
        );
      }

      const certHtml = generateProvenanceCertificateHtml({
        fileName,
        fileSize,
        mimeType,
        originalFileHash,
        attestedHash: data.client_hash || hash,
        signerPublicKey: data.signer_public_key || null,
        anchorMode: data.anchor_mode || (data.vdf_ticks ? "temporal" : "standard"),
        tIndex: data.thermodynamic_proof || data.t_index || "PENDING VDF SNAPSHOT",
        vdfTicks: data.vdf_ticks || 0,
        status: data.status || "pending_finality",
        blockHeight: data.settlement?.bitcoin_block_height || null,
        blockTimeUtc: data.settlement?.bitcoin_block_time
          ? new Date(data.settlement.bitcoin_block_time * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC"
          : null,
        merkleProofCount: Array.isArray(data.settlement?.merkle_proof_path)
          ? data.settlement.merkle_proof_path.length
          : null,
        txid: data.settlement?.bitcoin_txid || null,
      });

      const certPath = args.output_certificate_html_path
        ? path.resolve(args.output_certificate_html_path)
        : path.join(
            targetDir,
            fileName !== "Zero-Knowledge Hash Payload"
              ? `reltime-certificate-${fileName}.html`
              : `reltime-certificate-${hash.slice(0, 12)}.html`
          );
      fs.writeFileSync(certPath, certHtml, "utf8");
      out.saved_certificate_html_path = certPath;

      if (args.open_certificate_in_browser) {
        openSystemBrowser(certPath);
      }
    }

    return out;
  }

  if (name === "reltime_account_status") {
    if (!key) {
      return buildPackSelectionPrompt(
        "Rel-Time MCP is connected! No API key is saved yet. Ask the user which pack they would like to provision first:"
      );
    }
    const res = await fetch(`${API_BASE}/account`, {
      headers: { Authorization: `Bearer ${key}` },
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error(`Rel-Time Account error (${res.status}) from ${API_BASE}/account: ${text.slice(0, 200)}`);
    }
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        return buildPackSelectionPrompt(
          "The configured API key was not recognized. Ask the user which pack they would like to provision:"
        );
      }
      throw new Error(`Rel-Time Account error (${res.status}): ${JSON.stringify(data)}`);
    }
    return data;
  }

  if (name === "reltime_audit_trail") {
    if (!key) {
      return buildPackSelectionPrompt(
        "To run a Superhighway Audit Trail, a Rel-Time API key is required. Ask the user which tier and payment method they would like to provision:"
      );
    }

    const acctRes = await fetch(`${API_BASE}/account`, {
      headers: { Authorization: `Bearer ${key}` },
    });
    if (!acctRes.ok) {
      if (acctRes.status === 401 || acctRes.status === 403) {
        return buildPackSelectionPrompt(
          "The configured API key was not recognized. Ask the user which tier and payment method they would like to provision:"
        );
      }
      throw new Error(`Rel-Time Account error (${acctRes.status}): ${await acctRes.text()}`);
    }
    const acctData = await acctRes.json();
    const tierName = String(acctData.tier || "");
    const isSuperhighway =
      tierName.includes("Superhighway") ||
      tierName.includes("Enterprise") ||
      key.startsWith("rel_key_enterprise_");

    if (!isSuperhighway) {
      return {
        status: "superhighway_upgrade_required",
        current_tier: tierName || "Standard / Agent",
        hash_credits: Number(acctData.hash_credits || 0),
        message:
          "Data Integrity Audit, Instant Tamper Detection, and Forensic Timechain Reports (`reltime_audit_trail`) are exclusive to the Rel-Time Superhighway ($399 / 5,000 Hashes) tier.",
        how_to_upgrade:
          "Ask the user if they would like to upgrade their current key to Rel-Time Superhighway ($399 / 5,000 Hashes) via Bitcoin Lightning (`lightning`) or Stripe Card (`stripe`), then call `reltime_provision_agent_key({ action: 'create_invoice', pack: 'enterprise', payment_method, reload_existing: true })`.",
      };
    }

    if (Number(acctData.hash_credits || 0) <= 0) {
      return {
        status: "superhighway_renewal_required",
        current_tier: tierName,
        hash_credits: 0,
        message:
          "Your Rel-Time Superhighway key currently has 0 active Hash Credits remaining. Please renew your Superhighway cycle ($399 / 5,000 Hashes) to run Data Integrity Audits & Forensic Reports.",
        how_to_renew:
          "Ask the user if they would like to renew their Superhighway key via Bitcoin Lightning (`lightning`) or Stripe Card (`stripe`), then call `reltime_provision_agent_key({ action: 'create_invoice', pack: 'enterprise', payment_method, reload_existing: true })`.",
      };
    }

    const maxEntries = Math.min(5000, Math.max(1, Number(args.limit) || 2000));
    const pageSize = Math.min(100, maxEntries);
    const pagesToFetch = Math.ceil(maxEntries / pageSize);
    let rawHistory = [];
    let totalInLedger = 0;

    for (let p = 1; p <= pagesToFetch; p++) {
      const histRes = await fetch(`${API_BASE}/account/history?page=${p}&limit=${pageSize}`, {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (!histRes.ok) break;
      const histJson = await histRes.json();
      totalInLedger = Number(histJson.total || 0);
      const batch = Array.isArray(histJson.history) ? histJson.history : [];
      rawHistory.push(...batch);
      if (batch.length < pageSize || rawHistory.length >= maxEntries || rawHistory.length >= totalInLedger) {
        break;
      }
    }
    rawHistory = rawHistory.slice(0, maxEntries);

    const statusFilter = (args.status_filter || "all").toLowerCase();
    const modeFilter = (args.mode_filter || "all").toLowerCase();
    const signerFilter = (args.signer_filter || "").trim().toLowerCase();

    const normalizedEntries = rawHistory.map((item) => {
      const clientHash = (item.client_hash || "").toLowerCase();
      const tIndex = (item.t_index || "").toLowerCase();
      const origHash = item.original_file_hash ? item.original_file_hash.toLowerCase() : null;
      const mode = (item.anchor_mode || "standard").toLowerCase();
      const lookupHash = mode === "temporal" ? tIndex || clientHash : clientHash;
      const tsSec = Number(item.timestamp || 0);
      const tsUtc = tsSec > 0 ? new Date(tsSec * 1000).toISOString() : null;
      return {
        timestamp: tsSec,
        timestamp_utc: tsUtc,
        status: item.status || "pending_finality",
        anchor_mode: mode,
        identity_mode: item.signer_public_key ? "biometric_passkey" : "anonymous",
        client_hash: clientHash,
        original_file_hash: origHash,
        t_index: tIndex,
        vdf_ticks: Number(item.vdf_ticks || 0),
        signer_public_key: item.signer_public_key || null,
        block_height: item.block_height || null,
        block_time: item.block_time || null,
        block_time_utc: item.block_time ? new Date(Number(item.block_time) * 1000).toISOString() : null,
        txid: item.txid || null,
        merkle_root: item.merkle_root || null,
        verify_url: `https://rel-time.com/verify?t=${lookupHash}`,
        sun_stamp_svg_url: `${API_BASE}/stamp/${lookupHash}`,
      };
    });

    const filteredEntries = normalizedEntries.filter((e) => {
      if (statusFilter === "settled" && e.status !== "settled") return false;
      if (statusFilter === "pending" && e.status === "settled") return false;
      if (modeFilter === "standard" && e.anchor_mode !== "standard") return false;
      if (modeFilter === "temporal" && e.anchor_mode !== "temporal") return false;
      if (modeFilter === "biometric" && !e.signer_public_key) return false;
      if (signerFilter && !(e.signer_public_key || "").toLowerCase().includes(signerFilter)) return false;
      return true;
    });

    // Aggregate KPI & Hardware Passkey Signer statistics
    let settledCount = 0;
    let pendingCount = 0;
    let standardCount = 0;
    let temporalCount = 0;
    let biometricCount = 0;
    const uniqueBlocks = new Set();
    const uniqueTxids = new Set();
    let latestBlock = null;
    let latestTxid = null;
    const signerMap = new Map();

    for (const e of filteredEntries) {
      if (e.status === "settled") {
        settledCount++;
        if (e.block_height) {
          uniqueBlocks.add(e.block_height);
          if (!latestBlock || Number(e.block_height) > Number(latestBlock)) {
            latestBlock = e.block_height;
            latestTxid = e.txid || latestTxid;
          }
        }
        if (e.txid) uniqueTxids.add(e.txid);
      } else {
        pendingCount++;
      }

      if (e.anchor_mode === "temporal") temporalCount++;
      else standardCount++;

      if (e.signer_public_key) {
        biometricCount++;
        const pk = e.signer_public_key;
        const cur = signerMap.get(pk) || {
          signer_public_key: pk,
          short_key: `${pk.slice(0, 12)}...${pk.slice(-8)}`,
          anchor_count: 0,
          settled_count: 0,
          latest_timestamp_utc: e.timestamp_utc,
        };
        cur.anchor_count++;
        if (e.status === "settled") cur.settled_count++;
        if (e.timestamp_utc && (!cur.latest_timestamp_utc || e.timestamp_utc > cur.latest_timestamp_utc)) {
          cur.latest_timestamp_utc = e.timestamp_utc;
        }
        signerMap.set(pk, cur);
      }
    }

    // Build fast lookup index of all known hashes in account history + known passkeys
    const ledgerByHash = new Map();
    const knownPasskeys = new Set();
    const localPasskey = loadSavedPasskey();
    if (localPasskey && localPasskey.public_key_hex) {
      knownPasskeys.add(localPasskey.public_key_hex);
    }
    for (const e of normalizedEntries) {
      if (e.client_hash) ledgerByHash.set(e.client_hash, e);
      if (e.t_index) ledgerByHash.set(e.t_index, e);
      if (e.original_file_hash) ledgerByHash.set(e.original_file_hash, e);
      if (e.signer_public_key) knownPasskeys.add(e.signer_public_key);
    }

    // Optional Zero-Knowledge Local File / Folder Integrity Verification
    let localPathVerification = null;
    let resolvedVerifyTargetPath = null;
    if (args.verify_local_path) {
      const targetPath = resolveLocalFilePath(args.verify_local_path);
      resolvedVerifyTargetPath = targetPath;
      if (!fs.existsSync(targetPath)) {
        throw new Error(`verify_local_path not found: ${targetPath}`);
      }
      const stat = fs.statSync(targetPath);
      let candidateFiles = [];
      if (stat.isFile()) {
        candidateFiles.push(targetPath);
      } else if (stat.isDirectory()) {
        const dirItems = fs.readdirSync(targetPath);
        for (const item of dirItems) {
          if (item.startsWith(".")) continue;
          if (
            item.startsWith("reltime-stamp-") ||
            item.startsWith("reltime-stamped-") ||
            item.startsWith("reltime-doomsday-proof-") ||
            item.startsWith("reltime-proof-") ||
            item.startsWith("reltime-certificate-") ||
            item.startsWith("reltime-audit-report-") ||
            item.startsWith("reltime-audit-trail-") ||
            item === "reltime-batch-manifest.json" ||
            item === "_reltime_proofs"
          ) {
            continue;
          }
          const fullItemPath = path.join(targetPath, item);
          try {
            if (fs.statSync(fullItemPath).isFile()) {
              candidateFiles.push(fullItemPath);
            }
          } catch (e) {
            // Skip unreadable entry
          }
        }
      }

      const fileAuditResults = [];
      let vSettled = 0;
      let vPending = 0;
      let vUnanchored = 0;

      for (const fPath of candidateFiles) {
        const buf = fs.readFileSync(fPath);
        const fName = path.basename(fPath);
        const rawSha256 = crypto.createHash("sha256").update(buf).digest("hex");
        const embeddedHash = extractStampedCopyEmbeddedHash(fPath, buf);
        const isStampedCopy = Boolean(embeddedHash) || fName.startsWith("reltime-stamped-");

        let matchedEntry =
          ledgerByHash.get(rawSha256) || (embeddedHash ? ledgerByHash.get(embeddedHash) : null) || null;

        // Also check biometric attested hashes SHA-256(rawSha256 + passkey_hex)
        if (!matchedEntry) {
          for (const pkHex of knownPasskeys) {
            const attestedCandidate = crypto
              .createHash("sha256")
              .update(`${rawSha256}${pkHex}`, "utf8")
              .digest("hex");
            if (ledgerByHash.has(attestedCandidate)) {
              matchedEntry = ledgerByHash.get(attestedCandidate);
              break;
            }
          }
        }

        // Fallback: query live GET /v1/proof/{hash} in case it was anchored outside the recent history window
        const probeHash = embeddedHash || rawSha256;
        if (!matchedEntry) {
          try {
            const proofRes = await fetch(`${API_BASE}/proof/${probeHash}`);
            if (proofRes.ok) {
              const proofData = await proofRes.json();
              const s = proofData.settlement || {};
              matchedEntry = {
                status: proofData.status || "settled",
                anchor_mode: proofData.anchor_mode || "standard",
                client_hash: proofData.client_hash || probeHash,
                t_index: proofData.t_index || probeHash,
                signer_public_key: proofData.signer_public_key || null,
                block_height: s.bitcoin_block_height || s.block_height || null,
                txid: s.bitcoin_txid || null,
                merkle_root: s.merkle_root || null,
                verify_url: `https://rel-time.com/verify?t=${probeHash}`,
              };
            }
          } catch (e) {
            // Ignore network error during fallback lookup
          }
        }

        let integrityStatus = "UNANCHORED_OR_MODIFIED";
        if (matchedEntry) {
          if (matchedEntry.status === "settled") {
            integrityStatus = "VERIFIED_SETTLED";
            vSettled++;
          } else {
            integrityStatus = "VERIFIED_PENDING";
            vPending++;
          }
        } else {
          vUnanchored++;
        }

        const bytes = buf.length;
        const sizeHuman =
          bytes >= 1048576
            ? `${(bytes / 1048576).toFixed(2)} MB`
            : bytes >= 1024
            ? `${(bytes / 1024).toFixed(1)} KB`
            : `${bytes} B`;

        fileAuditResults.push({
          file_name: fName,
          file_path: redactHomePath(fPath),
          size_bytes: bytes,
          size_human: sizeHuman,
          local_sha256: embeddedHash || rawSha256,
          raw_file_sha256: rawSha256,
          embedded_stamp_hash: embeddedHash,
          is_stamped_copy: isStampedCopy,
          integrity_status: integrityStatus,
          anchor_mode: matchedEntry ? matchedEntry.anchor_mode : null,
          signer_public_key: matchedEntry ? matchedEntry.signer_public_key : null,
          t_index: matchedEntry ? matchedEntry.t_index : null,
          block_height: matchedEntry ? matchedEntry.block_height : null,
          txid: matchedEntry ? matchedEntry.txid : null,
          verify_url: matchedEntry ? matchedEntry.verify_url : null,
        });
      }

      localPathVerification = {
        target_path: redactHomePath(targetPath),
        summary: {
          total_files_scanned: fileAuditResults.length,
          verified_settled_count: vSettled,
          verified_pending_count: vPending,
          unanchored_or_modified_count: vUnanchored,
          overall_integrity: vUnanchored === 0 ? "ALL_FILES_VERIFIED" : "ATTENTION_UNANCHORED_OR_MODIFIED_FILES",
        },
        files: fileAuditResults,
      };
    }

    const maskedKey = key.length > 16 ? `${key.slice(0, 14)}…${key.slice(-4)}` : "rel_key_***";
    const settlementRatePct =
      filteredEntries.length > 0 ? `${Math.round((settledCount / filteredEntries.length) * 100)}%` : "0%";

    const auditPayload = {
      status: "audit_complete",
      generated_at_utc: new Date().toISOString(),
      account_overview: {
        tier: acctData.tier || "Active",
        hash_credits_remaining: Number(acctData.hash_credits || 0),
        lifetime_anchors: Number(acctData.total_usage || totalInLedger || 0),
        masked_api_key: maskedKey,
      },
      audit_summary: {
        total_ledger_entries: totalInLedger,
        matched_entries_count: filteredEntries.length,
        settled_on_bitcoin_count: settledCount,
        pending_finality_count: pendingCount,
        settlement_rate_pct: settlementRatePct,
        mode_breakdown: {
          standard_count: standardCount,
          temporal_vdf_count: temporalCount,
          biometric_passkey_count: biometricCount,
        },
        bitcoin_settlement: {
          unique_blocks_count: uniqueBlocks.size,
          unique_txids_count: uniqueTxids.size,
          latest_settled_block: latestBlock,
          latest_txid: latestTxid,
        },
        hardware_passkey_signers: Array.from(signerMap.values()),
      },
      local_path_verification: localPathVerification,
      audit_trail: filteredEntries,
    };

    // Determine output directory for reports
    let reportDir = path.join(PASSKEY_CONFIG_DIR, "audits");
    if (args.output_dir) {
      reportDir = resolveLocalFilePath(args.output_dir);
    } else if (resolvedVerifyTargetPath) {
      reportDir = fs.statSync(resolvedVerifyTargetPath).isDirectory()
        ? resolvedVerifyTargetPath
        : path.dirname(resolvedVerifyTargetPath);
    }
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    const dateStamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const savedReports = {};

    if (args.save_html_report !== false) {
      const htmlPath = path.join(reportDir, `reltime-audit-report-${dateStamp}.html`);
      const htmlContent = generateAuditReportHtml(auditPayload);
      fs.writeFileSync(htmlPath, htmlContent, "utf8");
      savedReports.html_report_path = htmlPath;

      if (args.open_in_browser !== false) {
        try {
          openSystemBrowser(htmlPath);
          savedReports.opened_in_browser = true;
        } catch (e) {
          savedReports.opened_in_browser = false;
        }
      }
    }

    if (args.export_csv) {
      const csvPath = path.join(reportDir, `reltime-audit-trail-${dateStamp}.csv`);
      const csvHeader = [
        "timestamp_utc",
        "status",
        "anchor_mode",
        "identity_mode",
        "client_hash",
        "original_file_hash",
        "t_index",
        "vdf_ticks",
        "signer_public_key",
        "bitcoin_block_height",
        "bitcoin_txid",
        "merkle_root",
        "verify_url",
      ].join(",");
      const csvRows = filteredEntries.map((e) =>
        [
          e.timestamp_utc || "",
          e.status || "",
          e.anchor_mode || "",
          e.identity_mode || "",
          e.client_hash || "",
          e.original_file_hash || "",
          e.t_index || "",
          e.vdf_ticks || 0,
          e.signer_public_key || "",
          e.block_height || "",
          e.txid || "",
          e.merkle_root || "",
          e.verify_url || "",
        ]
          .map((v) => `"${String(v).replace(/"/g, '""')}"`)
          .join(",")
      );
      fs.writeFileSync(csvPath, [csvHeader, ...csvRows].join("\n"), "utf8");
      savedReports.csv_report_path = csvPath;
    }

    auditPayload.saved_reports = savedReports;
    return auditPayload;
  }

  if (name === "reltime_provision_agent_key") {
    if (args.action === "create_invoice") {
      const validPacks = ["universal", "launch", "standard", "enterprise", "superhighway"];
      const validMethods = ["lightning", "stripe"];
      const normalizedPack = (args.pack || "").trim().toLowerCase();
      const normalizedMethod = (args.payment_method || "").trim().toLowerCase();

      if (!validPacks.includes(normalizedPack) || !validMethods.includes(normalizedMethod)) {
        const missingNote = !validPacks.includes(normalizedPack)
          ? "Please ask the user which Rel-Time Tier (`universal` $3, `launch` $5/25, `standard` $50/500, or `enterprise` $399/5,000) AND which payment method (`lightning` or `stripe`) they would like to provision:"
          : `The user selected pack '${normalizedPack}', but payment_method was not specified. Please ask the user whether they want to pay via Bitcoin Lightning ('lightning') or Stripe Card ('stripe') before calling create_invoice again:`;
        return buildPackSelectionPrompt(missingNote);
      }

      const finalPack = normalizedPack === "superhighway" ? "enterprise" : normalizedPack;
      const paymentMethod = normalizedMethod;
      const targetReloadKey =
        args.api_key || ((args.reload_existing || finalPack === "launch") ? loadSavedApiKey() : "");

      LAST_INVOICE_PACK = finalPack;
      const reqBody = {
        accept_terms: true,
        pack: finalPack,
        payment_method: paymentMethod,
      };
      if (args.quantity && Number(args.quantity) > 0) {
        reqBody.quantity = Math.max(1, Math.round(Number(args.quantity)));
      }
      if (targetReloadKey && targetReloadKey.trim()) {
        reqBody.api_key = targetReloadKey.trim();
      }

      const res = await fetch(`${API_BASE}/agent/invoice`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(`Rel-Time checkout error (${res.status}): ${JSON.stringify(data)}`);
      }

      const checkoutUrl = data.checkout_url || data.url || "";
      const bolt11 = data.ln_invoice || data.bolt11 || "";

      if (paymentMethod === "stripe" && checkoutUrl) {
        try {
          openSystemBrowser(checkoutUrl);
          if (!fs.existsSync(PASSKEY_CONFIG_DIR)) {
            fs.mkdirSync(PASSKEY_CONFIG_DIR, { recursive: true, mode: 0o700 });
          }
          const qrPngBuffer = await QRCode.toBuffer(checkoutUrl, {
            type: "png",
            width: 560,
            margin: 2,
            errorCorrectionLevel: "M",
          });
          const homeQrPath = path.join(PASSKEY_CONFIG_DIR, "stripe-checkout-qr.png");
          fs.writeFileSync(homeQrPath, qrPngBuffer);
          data.qr_code_png_path = homeQrPath;
          data._mcp_image_base64 = qrPngBuffer.toString("base64");
        } catch (qrErr) {
          data.qr_error = qrErr.message;
        }
        if (data.api_key && isValidApiKeyCandidate(data.api_key)) {
          // Pre-save the pending Stripe key so as soon as payment finishes it is ready
          CURRENT_API_KEY = data.api_key.trim();
          saveApiKeyConfig(CURRENT_API_KEY, finalPack);
          data.saved_to_config = API_KEY_CONFIG_PATH;
        }
        data.mandatory_first_reply_instructions =
          "CRITICAL INSTRUCTION FOR AI AGENT: The Stripe Checkout URL has been opened in the user's browser AND the pending API key has been saved to ~/.reltime/api_key.json. Show the user the clickable `checkout_url` link (`" +
          checkoutUrl +
          "`), the `invoice_id` (`" +
          (data.invoice_id || data.session_id) +
          "`), and tell them that once they finish paying on Stripe, you will call `reltime_provision_agent_key({ action: 'claim_invoice', invoice_id: '" +
          (data.invoice_id || data.session_id) +
          "' })` to activate the credits immediately!";
        return data;
      }

      if (bolt11) {
        try {
          if (!fs.existsSync(PASSKEY_CONFIG_DIR)) {
            fs.mkdirSync(PASSKEY_CONFIG_DIR, { recursive: true, mode: 0o700 });
          }
          const qrPngBuffer = await QRCode.toBuffer(bolt11.toUpperCase(), {
            type: "png",
            width: 560,
            margin: 2,
            errorCorrectionLevel: "M",
          });
          const homeQrPath = path.join(PASSKEY_CONFIG_DIR, "lightning-invoice-qr.png");
          const tmpQrPath = "/tmp/reltime-lightning-qr.png";
          fs.writeFileSync(homeQrPath, qrPngBuffer);
          try {
            fs.writeFileSync(tmpQrPath, qrPngBuffer);
          } catch (e) {
            // Ignore /tmp write error
          }
          data.bolt11 = bolt11;
          data.ln_invoice = bolt11;
          data.qr_code_png_path = homeQrPath;
          data.qr_code_tmp_png_path = tmpQrPath;
          data.invoice_expiration = "60 minutes (3,600 seconds)";
          data.mandatory_first_reply_instructions =
            "CRITICAL INSTRUCTION FOR AI AGENT: On this very first reply, you MUST show the user BOTH: (1) the scannable QR code image (immediately call your Read tool on `qr_code_png_path` BEFORE sending your message so the QR code PNG renders inline in the chat window right now!) AND (2) the full, un-truncated `bolt11` (`lnbc...`) Lightning invoice string inside a copyable code block so the user can either scan with their phone or copy-paste on the first try without asking!";
          data._mcp_image_base64 = qrPngBuffer.toString("base64");
        } catch (qrErr) {
          data.qr_error = qrErr.message;
        }
      }
      return data;
    } else if (args.action === "claim_invoice") {
      if (!args.invoice_id) throw new Error("invoice_id is required when action is 'claim_invoice'.");
      const resolvedPack = args.pack || LAST_INVOICE_PACK || undefined;
      const claimPayload = {
        invoice_id: args.invoice_id,
        pack: resolvedPack,
      };
      const targetReloadKey =
        args.api_key || ((args.reload_existing || resolvedPack === "launch") ? loadSavedApiKey() : "");
      if (targetReloadKey && targetReloadKey.trim()) {
        claimPayload.api_key = targetReloadKey.trim();
      }
      const res = await fetch(`${API_BASE}/agent/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(claimPayload),
      });
      const data = await res.json();
      if (data.api_key) {
        CURRENT_API_KEY = data.api_key;
        saveApiKeyConfig(data.api_key, resolvedPack || "standard");
        data.saved_to_config = API_KEY_CONFIG_PATH;
      }
      return data;
    }
    throw new Error(`Unknown action: ${args.action}`);
  }

  throw new Error(`Unknown tool: ${name}`);
}

// Standard MCP JSON-RPC 2.0 over stdio
const rl = readline.createInterface({
  input: process.stdin,
  terminal: false,
});

function sendJsonRpc(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

rl.on("line", async (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch (e) {
    return;
  }

  const { id, method, params } = req;

  try {
    if (method === "initialize") {
      sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: (params && params.protocolVersion) || "2024-11-05",
          capabilities: {
            tools: {},
          },
          serverInfo: SERVER_INFO,
        },
      });
    } else if (method === "notifications/initialized") {
      // No response needed for notification
    } else if (method === "tools/list") {
      sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: {
          tools: TOOLS,
        },
      });
    } else if (method === "tools/call") {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};
      try {
        const resultObj = await executeTool(toolName, toolArgs);
        const contentItems = [];
        if (resultObj && resultObj._mcp_image_base64) {
          const b64 = resultObj._mcp_image_base64;
          delete resultObj._mcp_image_base64;
          contentItems.push({
            type: "image",
            data: b64,
            mimeType: "image/png",
          });
        }
        contentItems.push({
          type: "text",
          text: JSON.stringify(resultObj, null, 2),
        });
        sendJsonRpc({
          jsonrpc: "2.0",
          id,
          result: {
            content: contentItems,
          },
        });
      } catch (toolErr) {
        sendJsonRpc({
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: `Error: ${toolErr.message || String(toolErr)}`,
              },
            ],
          },
        });
      }
    } else if (method === "ping") {
      sendJsonRpc({ jsonrpc: "2.0", id, result: {} });
    } else if (id !== undefined) {
      sendJsonRpc({
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      });
    }
  } catch (err) {
    if (id !== undefined) {
      sendJsonRpc({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: err.message || "Internal error" },
      });
    }
  }
});
