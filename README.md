# `@rel-time/mcp-server` — Official Rel-Time MCP Server

Official Model Context Protocol (MCP) server for **[Rel-Time](https://rel-time.com)** — enabling Claude Desktop, Cursor, Windsurf, and Google Antigravity agents to:
1. **Hash local files with 100% Zero-Knowledge** (your file bytes never leave your computer).
2. **Execute both Anonymous & Biometric (Passkey) Anchors** (`SHA256(File_Hash + Passkey_PubKey)`) using TouchID, FaceID, or YubiKey via `https://rel-time.com/mcp-passkey`.
3. **Anchor SHA-256 hashes to the Bitcoin Timechain & Rel-Time VDF** (`POST /v1/anchor`).
4. **Generate & overlay 64-ray Sun-Stamps onto PDFs and Images** (`reltime-stamped-<name>.pdf` / `.png`).
5. **Verify Bitcoin block settlement & Merkle proofs** (`GET /v1/proof/{hash}`).
6. **Self-provision or Reload all 4 Rel-Time Tiers via Bitcoin Lightning or Stripe Card** (`Universal Anchor $3`, `Agent Launch Pack $5 / 25`, `Autonomous Agents $50 / 500`, and `Rel-Time Superhighway $399 / 5,000`).
7. **Run a Superhighway Cryptographic Audit Trail & Local Folder Integrity Check** (`reltime_audit_trail`), generating an interactive HTML Audit Dashboard with Corporate Hardware Passkey (`signer_public_key`) attribution and Bitcoin block verification.

---

## Quick Setup (Claude Desktop / Claude Code / Cursor / Windsurf / Antigravity)

Add the following to your `.mcp.json`, `claude_desktop_config.json`, or `.cursor/mcp.json` (no API key or `.zshrc` environment variables needed to start!):

```json
{
  "mcpServers": {
    "rel-time": {
      "command": "npx",
      "args": ["-y", "@rel-time/mcp-server@latest"]
    }
  }
}
```

When you start a fresh chat and ask to anchor a file or provision a key, `@rel-time/mcp-server` automatically prompts your agent to ask which tier and payment method (**Bitcoin Lightning** or **Stripe Card**) you want first:
1. **Universal Anchor (`pack: "universal"`, `$3 / anchor`):** Priority 10-Minute Bitcoin Queue · Standard Mode (Data Integrity + Biometric or Anonymous).
2. **Agent Launch Pack (`pack: "launch"`, `$5 / 25 Hashes`, max 3 per key):** Priority 10-Minute Bitcoin Queue · Standard Mode · Includes 64-Ray Sun-Stamp, 1-Click Stamped Copy (`.PDF`/`.PNG`), 4-Plate Certificate, and `.JSON` Doomsday Proof.
3. **Autonomous Agents (`pack: "standard"`, `$50 / 500 Hashes`):** Dynamic 6-Hour Batch Queue · Supports both Temporal Mode (`T_index` sub-second VDF sequencing) and Standard Mode · Reloadable anytime (`+500` credits / `$50`).
4. **Rel-Time Superhighway (`pack: "enterprise"`, `$399 / 5,000 Hashes`):** Priority 10-Minute Bitcoin Queue · Temporal Mode (`T_index`) + Standard Mode + Data Integrity Audit & Instant Tamper Detection.

Once paid via Lightning or Stripe (or if you pass an existing `rel_key_...` key), the MCP server automatically saves your API key to `~/.reltime/api_key.json` (`0600` permissions) — no app restart or `.zshrc` edits required.

---

## Available MCP Tools

| Tool Name | Requires Key? | What It Does |
| :--- | :---: | :--- |
| `reltime_anchor_file` | Yes | Computes the SHA-256 hash of a local file **on your machine** (0 bytes uploaded), supports `biometric: true` for **Biometric Anchors** (TouchID/FaceID/YubiKey), anchors via `POST /v1/anchor`, saves `reltime-stamp-<filename>.svg`, `reltime-certificate-<filename>.html`, and `reltime-doomsday-proof-<filename>.json`, and automatically outputs a clickable **Stamped Copy** (`reltime-stamped-<name>.pdf` or `.png`). |
| `reltime_anchor_folder` | Yes | **Bulk folder anchoring (10 to 5,000+ files in one call):** Hashes all files in a local folder 100% locally, supports `biometric: true` (Passkey) or Anonymous mode, automatically skips already-anchored files (safe to resume), and keeps your directory clean by storing per-file Doomsday Proofs inside `<folder>/_reltime_proofs/` plus a master `reltime-batch-manifest.json`. |
| `reltime_audit_trail` | Yes | Fetches the account's chronological anchor ledger (`GET /v1/account/history`), aggregates Bitcoin block settlements, VDF `T_index` ticks, and Corporate Hardware Passkey (`signer_public_key`) signatures, optionally verifies a local file or entire folder bit-for-bit (`verify_local_path`), and spins up a self-contained interactive HTML Audit Report (`reltime-audit-report-*.html`) in your browser. |
| `reltime_link_passkey` | **No** | Opens `https://rel-time.com/mcp-passkey` in the system browser so the user can touch TouchID / FaceID / YubiKey once, saving `{ public_key_hex, passkey_signature }` to `~/.reltime/passkey.json` for seamless Biometric Anchors. |
| `reltime_stamp_file` | **No** | Overlays the authentic 64-ray Sun-Stamp onto the bottom-right corner of any local PDF or Image (`.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`) 100% locally. |
| `reltime_anchor_hash` | Yes | Anchors any 64-char hex SHA-256 hash in `standard` (10-min Express / Integrity) or `temporal` (VDF sequence ordering) mode. |
| `reltime_get_sun_stamp` | **No** | Fetches the deterministic 64-ray SVG Sun-Stamp (`GET /v1/stamp/{hash}`) and returns ready-to-paste Markdown/HTML badge snippets. |
| `reltime_check_proof` | **No** | Queries `GET /v1/proof/{hash}` for Bitcoin TXID, Block Height, UTC Timestamp, and Merkle inclusion path, and optionally saves/updates the `.json` Doomsday Proof receipt on disk. |
| `reltime_account_status` | Yes | Checks remaining Hash Credits and tier status (`GET /v1/account`). |
| `reltime_provision_agent_key` | **No** | Provisions or reloads any of the 4 Rel-Time Tiers (`universal` `$3`, `launch` `$5/25`, `standard` `$50/500`, `enterprise` `$399/5,000`) via **Bitcoin Lightning** or **Stripe Card**. |
