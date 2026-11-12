#!/usr/bin/env node
/**
 * Discord Badge Maximizer - Game Time & Game Variety Telemetry Engine (Node.js)
 * Emits authentic client-side game telemetry events directly to /api/v9/science
 * to claim Tier 10 Game Time (5,000h) and Tier 10 Game Variety (100+ titles).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline/promises";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import dotenv from "dotenv";
import { decryptToken, encryptToken } from "./crypto_vault.js";

const __filename = fileURLToPath(import.meta.url);
const WORKSPACE_DIR = path.dirname(__filename);
const STATE_STORAGE_PATH = path.join(WORKSPACE_DIR, "session.json");
const DATABASE_STORAGE_PATH = path.join(WORKSPACE_DIR, "data", "games.json");

dotenv.config({ path: path.join(WORKSPACE_DIR, ".env") });

export const REST_IDENTITY_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true";
export const DISCORD_USERS_API = "https://discord.com/api/v9/users";
export const TELEMETRY_INGEST_URL = "https://discord.com/api/v9/science";
export const UPSTREAM_METRICS_URL = "https://cordapi.dolfi.es/api/v2/properties/windows";
export const DISCORD_CATALOG_URL = "https://cdn.discordapp.com/detectables/games.json";

export const DISPATCH_BATCH_LIMIT = 50;
export const NETWORK_COOLDOWN_SEC = 0.3;
export const TOKEN_EXPIRY_THRESHOLD_SEC = 12 * 3600;

export const DESKTOP_CLIENT_VERSION = "1.0.9253";
export const DESKTOP_BUILD_IDENTIFIER = 594031;
export const DESKTOP_BUILD_NUMBER = DESKTOP_BUILD_IDENTIFIER;
export const PLATFORM_BUILD_IDENTIFIER = 88414;
export const PLATFORM_OS_REVISION = "10.0.26200";
export const USER_AGENT_IDENTIFIER =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 " +
  "Electron/42.7.1 Safari/537.36";

const POWERSHELL_PE_ANALYZER = `param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
`;

export function extractAccountSnowflake(authToken) {
  try {
    const prefix = String(authToken || "").split(".", 1)[0];
    const pad = "=".repeat((-prefix.length % 4 + 4) % 4);
    return Buffer.from(prefix + pad, "base64").toString("utf-8");
  } catch {
    return "";
  }
}

export function buildBinarySignature(accountId, filePath = "", activePid = 0) {
  if (process.platform !== "win32") {
    throw new Error("Fingerprint generation requires a Windows runtime.");
  }
  const tempScript = path.join(os.tmpdir(), `sig_gen_${crypto.randomUUID().replace(/-/g, "")}.ps1`);
  fs.writeFileSync(tempScript, POWERSHELL_PE_ANALYZER, "utf8");
  try {
    const args = [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      tempScript,
      "-UserId",
      accountId,
    ];
    if (activePid) {
      args.push("-ProcessId", String(activePid));
    } else if (filePath) {
      args.push("-Path", filePath);
    }
    const output = execFileSync("powershell", args, {
      encoding: "utf8",
      timeout: 60000,
      windowsHide: true,
    });
    const lines = output
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    if (!lines.length) {
      throw new Error("Fingerprint generator yielded empty output.");
    }
    return lines[lines.length - 1];
  } finally {
    try {
      fs.unlinkSync(tempScript);
    } catch {
      // Ignore
    }
  }
}

export class TerminalInterface {
  static COLOR_ALERT = "\x1b[91m";
  static COLOR_PRIMARY = "\x1b[38;5;208m";
  static COLOR_SUCCESS = "\x1b[92m";
  static COLOR_NOTICE = "\x1b[93m";
  static COLOR_TEXT = "\x1b[97m";
  static COLOR_MUTED = "\x1b[90m";
  static COLOR_RESET = "\x1b[0m";

  renderTimestamp() {
    const d = new Date();
    const timeStr = [d.getHours(), d.getMinutes(), d.getSeconds()]
      .map((n) => String(n).padStart(2, "0"))
      .join(":");
    return `${TerminalInterface.COLOR_MUTED}${timeStr}${TerminalInterface.COLOR_RESET}`;
  }

  writeStatus(symbol, target, message, color) {
    console.log(
      `  ${this.renderTimestamp()} ${symbol} ${TerminalInterface.COLOR_TEXT}${target}${TerminalInterface.COLOR_RESET} ` +
        `${TerminalInterface.COLOR_MUTED}·${TerminalInterface.COLOR_RESET} ${color}${message}${TerminalInterface.COLOR_RESET}`
    );
  }

  success(target, message) {
    this.writeStatus(
      `${TerminalInterface.COLOR_SUCCESS}✓${TerminalInterface.COLOR_RESET}`,
      target,
      message,
      TerminalInterface.COLOR_SUCCESS
    );
  }

  dispatched(target, message) {
    this.writeStatus(
      `${TerminalInterface.COLOR_MUTED}·${TerminalInterface.COLOR_RESET} ${TerminalInterface.COLOR_SUCCESS}posted${TerminalInterface.COLOR_RESET}`,
      target,
      message,
      TerminalInterface.COLOR_SUCCESS
    );
  }

  warning(target, message) {
    this.writeStatus(
      `${TerminalInterface.COLOR_NOTICE}!${TerminalInterface.COLOR_RESET}`,
      target,
      message,
      TerminalInterface.COLOR_NOTICE
    );
  }

  failure(target, message) {
    this.writeStatus(
      `${TerminalInterface.COLOR_ALERT}✗${TerminalInterface.COLOR_RESET}`,
      target,
      message,
      TerminalInterface.COLOR_ALERT
    );
  }

  log(message) {
    console.log(
      `  ${this.renderTimestamp()} ${TerminalInterface.COLOR_MUTED}·${TerminalInterface.COLOR_RESET} ${TerminalInterface.COLOR_TEXT}${message}${TerminalInterface.COLOR_RESET}`
    );
  }

  getTerminalWidth() {
    return process.stdout.columns || 80;
  }

  createBorder(char = "═") {
    const width = this.getTerminalWidth();
    return char.repeat(Math.max(10, width - 2));
  }

  separator(char = "─") {
    const width = this.getTerminalWidth();
    console.log(`\x1b[96m${char.repeat(width)}${TerminalInterface.COLOR_RESET}`);
  }

  clearViewport() {
    process.stdout.write("\x1b[2J\x1b[3J\x1b[H");
  }

  displayHeader() {
    this.clearViewport();
    const width = this.getTerminalWidth();
    const border = this.createBorder("═");
    const title = "DISCORD BADGE MAXIMIZER";
    const subtitle = "Playtime & Game Variety Telemetry Engine (Node.js)";

    const padT = " ".repeat(Math.max(0, Math.floor((width - title.length - 2) / 2)));
    const padTR = " ".repeat(Math.max(0, width - title.length - 2 - padT.length));
    const padS = " ".repeat(Math.max(0, Math.floor((width - subtitle.length - 2) / 2)));
    const padSR = " ".repeat(Math.max(0, width - subtitle.length - 2 - padS.length));

    console.log();
    console.log(`\x1b[96m╔${border}╗${TerminalInterface.COLOR_RESET}`);
    console.log(
      `\x1b[96m║${TerminalInterface.COLOR_RESET}${padT}${TerminalInterface.COLOR_TEXT}${title}${TerminalInterface.COLOR_RESET}${padTR}\x1b[96m║${TerminalInterface.COLOR_RESET}`
    );
    console.log(
      `\x1b[96m║${TerminalInterface.COLOR_RESET}${padS}${TerminalInterface.COLOR_MUTED}${subtitle}${TerminalInterface.COLOR_RESET}${padSR}\x1b[96m║${TerminalInterface.COLOR_RESET}`
    );
    console.log(`\x1b[96m╚${border}╝${TerminalInterface.COLOR_RESET}`);
    console.log();
  }
}

export class AccountSessionState {
  constructor(data = {}) {
    this.token = data.token || "";
    this.cookie = data.cookie || "";
    this.fingerprint = data.fingerprint || "";
    this.analytics_token = data.analytics_token || "";
    this.fetched_at = data.fetched_at || 0;
    this.used_games = Array.isArray(data.used_games) ? data.used_games : [];
    this.total_games_claimed = data.total_games_claimed || 0;
    this.total_hours_claimed = data.total_hours_claimed || 0.0;
    this._filepath = data._filepath || null;
  }

  static restore(customPath = null) {
    const target = customPath || STATE_STORAGE_PATH;
    const instance = new AccountSessionState({ _filepath: target });

    if (fs.existsSync(target)) {
      try {
        const raw = JSON.parse(fs.readFileSync(target, "utf8"));
        Object.assign(instance, raw);
        instance._filepath = target;

        const uidStr =
          target && path.parse(target).name && /^\d+$/.test(path.parse(target).name)
            ? path.parse(target).name
            : "";
        instance.token = decryptToken(instance.token, uidStr);
        instance.cookie = decryptToken(instance.cookie, uidStr);
      } catch {
        // Ignore read errors
      }
    }

    if (!customPath) {
      if (!instance.token && process.env.DISCORD_TOKEN) {
        instance.token = process.env.DISCORD_TOKEN.trim();
      }
      if (!instance.cookie && process.env.DISCORD_COOKIE) {
        instance.cookie = process.env.DISCORD_COOKIE.trim();
      }
    }

    return instance;
  }

  persist(customPath = null) {
    const target = customPath || this._filepath || STATE_STORAGE_PATH;
    const dir = path.dirname(target);
    fs.mkdirSync(dir, { recursive: true });

    let existing = {};
    if (fs.existsSync(target)) {
      try {
        existing = JSON.parse(fs.readFileSync(target, "utf8"));
      } catch {
        // Ignore
      }
    }

    const saveData = {
      token: this.token,
      cookie: this.cookie,
      fingerprint: this.fingerprint,
      analytics_token: this.analytics_token,
      fetched_at: this.fetched_at,
      used_games: this.used_games,
      total_games_claimed: this.total_games_claimed,
      total_hours_claimed: this.total_hours_claimed,
    };

    const uidStr =
      target && path.parse(target).name && /^\d+$/.test(path.parse(target).name)
        ? path.parse(target).name
        : "";
    if (saveData.token) {
      saveData.token = encryptToken(saveData.token, uidStr);
    }
    if (saveData.cookie) {
      saveData.cookie = encryptToken(saveData.cookie, uidStr);
    }

    Object.assign(existing, saveData);
    fs.writeFileSync(target, JSON.stringify(existing, null, 2), "utf8");
  }

  get requiresRefresh() {
    return (
      !this.analytics_token ||
      Date.now() / 1000 - this.fetched_at > TOKEN_EXPIRY_THRESHOLD_SEC
    );
  }

  get hasCredentials() {
    return Boolean(this.token.trim()) && Boolean(this.cookie.trim());
  }
}

export function generateFallbackProperties() {
  return {
    os: "Windows",
    browser: "Discord Client",
    release_channel: "stable",
    client_version: DESKTOP_CLIENT_VERSION,
    os_version: PLATFORM_OS_REVISION,
    os_arch: "x64",
    app_arch: "x64",
    system_locale: "en-US",
    has_client_mods: false,
    browser_user_agent: USER_AGENT_IDENTIFIER,
    browser_version: "42.7.1",
    os_sdk_version: "26200",
    client_build_number: DESKTOP_BUILD_IDENTIFIER,
    native_build_number: PLATFORM_BUILD_IDENTIFIER,
    client_event_source: null,
    client_app_state: "focused",
  };
}

export async function assembleSuperProperties(signatureId, sessionId) {
  let propertiesPayload;
  try {
    const res = await fetch(UPSTREAM_METRICS_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": USER_AGENT_IDENTIFIER,
      },
      body: "{}",
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const data = await res.json();
      propertiesPayload = data.properties;
    }
  } catch {
    // Fall back to local properties
  }

  if (!propertiesPayload) {
    propertiesPayload = generateFallbackProperties();
  }

  propertiesPayload.client_launch_id = crypto.randomUUID();
  propertiesPayload.launch_signature = signatureId;
  propertiesPayload.client_heartbeat_session_id = sessionId;

  const serialized = Buffer.from(JSON.stringify(propertiesPayload), "utf8");
  return serialized.toString("base64");
}

export async function requestAnalyticsCredential(authToken, superPropertiesB64) {
  const res = await fetch(REST_IDENTITY_URL, {
    headers: {
      authorization: authToken,
      "user-agent": USER_AGENT_IDENTIFIER,
      "x-super-properties": superPropertiesB64,
    },
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`Authentication rejected by endpoint (HTTP ${res.status})`);
  }

  const parsed = await res.json();
  const credential = parsed.analytics_token;
  if (!credential) {
    throw new Error("Upstream response omitted analytics_token field.");
  }
  return credential;
}

export async function synchronizeCredentials(state, superPropsB64) {
  if (!state.requiresRefresh) {
    return;
  }
  state.analytics_token = await requestAnalyticsCredential(state.token, superPropsB64);
  state.fetched_at = Math.floor(Date.now() / 1000);
  state.persist();
}

export class RuntimeClientContext {
  constructor(heartbeatSessionId, launchSignatureId, encodedProperties) {
    this.heartbeat_session_id = heartbeatSessionId;
    this.launch_signature_id = launchSignatureId;
    this.encoded_properties = encodedProperties;
  }

  static async initialize() {
    const hbSession = crypto.randomUUID();
    const launchSig = crypto.randomUUID();
    const encoded = await assembleSuperProperties(launchSig, hbSession);
    return new RuntimeClientContext(hbSession, launchSig, encoded);
  }
}

export class DetectableTitle {
  constructor(titleId, displayName, binaryName) {
    this.title_id = String(titleId);
    this.display_name = displayName;
    this.binary_name = binaryName;
  }
}

export function identifyWindowsBinary(gameRecord) {
  const exes = gameRecord.executables || [];
  for (const target of exes) {
    if (target.os === "win32" && target.name) {
      return target.name;
    }
  }
  return "game.exe";
}

export async function fetchRemoteCatalog() {
  const res = await fetch(DISCORD_CATALOG_URL, {
    headers: { "User-Agent": "Mozilla/5.0" },
    signal: AbortSignal.timeout(30000),
  });
  const content = await res.text();
  try {
    fs.mkdirSync(path.dirname(DATABASE_STORAGE_PATH), { recursive: true });
    fs.writeFileSync(DATABASE_STORAGE_PATH, content, "utf8");
  } catch {
    // Ignore cache write error
  }
  return content;
}

export function parseCatalogEntries(rawJson) {
  const payload = JSON.parse(rawJson);
  const catalog = [];
  const registeredIds = new Set();

  for (const item of payload) {
    const recordId = String(item.id || "");
    if (!/^\d+$/.test(recordId) || registeredIds.has(recordId)) {
      continue;
    }
    const hasWin32 = (item.executables || []).some(
      (entry) => entry.os === "win32" && entry.name
    );
    if (!hasWin32) {
      continue;
    }
    registeredIds.add(recordId);
    catalog.push(
      new DetectableTitle(recordId, item.name || "Unknown Game", identifyWindowsBinary(item))
    );
  }

  return catalog;
}

export async function loadGameCatalog() {
  if (fs.existsSync(DATABASE_STORAGE_PATH)) {
    try {
      const cachedContent = fs.readFileSync(DATABASE_STORAGE_PATH, "utf8").trim();
      if (cachedContent) {
        const titles = parseCatalogEntries(cachedContent);
        if (titles.length) {
          return titles;
        }
      }
    } catch {
      // Ignore cache parse error
    }
  }

  try {
    const remoteContent = await fetchRemoteCatalog();
    return parseCatalogEntries(remoteContent);
  } catch {
    return [];
  }
}

export class TelemetryEventFabricator {
  constructor(state, context) {
    this.state = state;
    this.context = context;
    this._sequenceIndex = 0;
  }

  incrementSequence() {
    this._sequenceIndex += 1;
    return this._sequenceIndex;
  }

  constructLaunchPayload(title) {
    const timestampNow = Date.now();
    const attributes = {
      client_track_timestamp: timestampNow,
      client_heartbeat_session_id: this.context.heartbeat_session_id,
      event_sequence_number: this.incrementSequence(),
      game: title.display_name,
      game_id: title.title_id,
      verified: true,
      elevated: false,
      is_launcher: false,
      game_platform: "desktop",
      detection_method: "verified_game",
      is_overlay_enabled: false,
      is_overlay_game_enabled: true,
      is_overlay_game_source: "OOP_DEFAULT_DATABASE",
      fullscreen_type: "UNKNOWN",
      hardware_display_count: 1,
      overlay_method: "Disabled",
      activity_status_enabled: true,
      activity_status_shared_guilds: [],
      current_user_status: "online",
      game_detection_enabled: true,
      executable_path: title.binary_name,
      voice_channel_id: null,
      voice_channel_type: null,
      voice_channel_bitrate: null,
      voice_channel_guild_id: null,
      hidden_by_distributor: false,
      game_metadata: null,
      executable_fingerprint: this.state.fingerprint || undefined,
      client_performance_cpu: null,
      client_performance_memory: null,
      cpu_core_count: null,
      accessibility_features: 0,
      rendered_locale: "en-US",
      launch_signature: this.context.launch_signature_id,
      client_rtc_state: null,
      client_app_state: "focused",
      client_send_timestamp: timestampNow,
    };
    if (!this.state.fingerprint) {
      delete attributes.executable_fingerprint;
    }
    return { type: "launch_game", properties: attributes };
  }

  constructHeartbeatPayload(title, durationMs, sessionToken, isInitial, isFinal, eventTimeMs = null) {
    const trackedTime = eventTimeMs !== null ? eventTimeMs : Date.now();
    return {
      type: "running_game_heartbeat",
      properties: {
        client_track_timestamp: trackedTime,
        client_heartbeat_session_id: this.context.heartbeat_session_id,
        event_sequence_number: this.incrementSequence(),
        game_id: title.title_id,
        game_name: title.display_name,
        game_metadata: null,
        game_executable: title.binary_name,
        game_detection_enabled: true,
        initial_heartbeat: isInitial,
        final_heartbeat: isFinal,
        game_session_id: sessionToken,
        duration_tracked_ms: durationMs,
        rtc_connection_id: null,
        media_session_id: null,
        launch_signature: this.context.launch_signature_id,
        client_app_state: "focused",
        client_send_timestamp: trackedTime,
      },
    };
  }

  assembleCompleteSession(title, durationMs) {
    const sessionId = crypto.randomUUID();
    const currentTime = Date.now();
    let originTime = currentTime - durationMs;
    if (originTime < 0) {
      originTime = currentTime;
    }

    return [
      this.constructHeartbeatPayload(title, 0, sessionId, true, false, originTime),
      this.constructLaunchPayload(title),
      this.constructHeartbeatPayload(title, durationMs, sessionId, false, true, currentTime),
    ];
  }

  async postTelemetryBatch(events) {
    const envelope = {
      token: this.state.analytics_token,
      events: events,
    };
    const encodedBody = JSON.stringify(envelope);

    try {
      const res = await fetch(TELEMETRY_INGEST_URL, {
        method: "POST",
        headers: {
          accept: "*/*",
          "accept-language": "en-US",
          authorization: this.state.token,
          "content-type": "application/json",
          cookie: this.state.cookie,
          origin: "https://discord.com",
          referer: "https://discord.com/channels/@me",
          "user-agent": USER_AGENT_IDENTIFIER,
          "x-debug-options": "bugReporterEnabled",
          "x-discord-locale": "en-US",
          "x-discord-timezone": "UTC",
          "x-super-properties": this.context.encoded_properties,
        },
        body: encodedBody,
        signal: AbortSignal.timeout(15000),
      });
      return res.status;
    } catch {
      return 0;
    }
  }
}

export class IngestionPipeline {
  constructor(fabricator, terminal) {
    this.fabricator = fabricator;
    this.terminal = terminal;
  }

  async executeStream(titles, sessionBuilder) {
    const totalRecords = titles.length;
    let processedSuccessfully = 0;
    let batchIndex = 1;

    for (let i = 0; i < titles.length; i += DISPATCH_BATCH_LIMIT) {
      const partition = titles.slice(i, i + DISPATCH_BATCH_LIMIT);
      const accumulatedEvents = [];
      for (const target of partition) {
        accumulatedEvents.push(...sessionBuilder(target));
      }

      const httpStatus = await this.fabricator.postTelemetryBatch(accumulatedEvents);
      if (httpStatus === 204) {
        processedSuccessfully += partition.length;
        this.terminal.dispatched(
          `batch ${batchIndex}`,
          `${processedSuccessfully}/${totalRecords} titles accepted`
        );
      } else if (httpStatus === 401 || httpStatus === 403) {
        this.terminal.failure(
          `batch ${batchIndex}`,
          `[${httpStatus}] Authentication failed. Refresh token/cookie.`
        );
        return processedSuccessfully;
      } else {
        this.terminal.warning(`batch ${batchIndex}`, `HTTP ${httpStatus}`);
      }

      batchIndex++;
      await new Promise((r) => setTimeout(r, NETWORK_COOLDOWN_SEC * 1000));
    }

    return processedSuccessfully;
  }
}

export class ApplicationController {
  constructor(state = null, sessionPath = null) {
    this.terminal = new TerminalInterface();
    this.session_path = sessionPath;
    if (state !== null) {
      this.state = state;
    } else if (sessionPath !== null) {
      this.state = AccountSessionState.restore(sessionPath);
    } else {
      this.state = AccountSessionState.restore();
    }
    this.runtime_context = null;
    this.fabricator = null;
    this.catalog = [];
  }

  async renewSession() {
    this.runtime_context = await RuntimeClientContext.initialize();
    this.fabricator = new TelemetryEventFabricator(this.state, this.runtime_context);
  }

  filterTitleSelection(desiredAmount) {
    const existingPool = new Set(this.catalog.map((i) => i.title_id));
    const unprocessed = this.catalog
      .map((i) => i.title_id)
      .filter((id) => !this.state.used_games.includes(id));
    const processed = this.state.used_games.filter((id) => existingPool.has(id));

    let chosen = [];
    if (unprocessed.length >= desiredAmount) {
      chosen = unprocessed.slice(0, desiredAmount);
    } else {
      chosen = [...unprocessed];
      if (processed.length) {
        const needed = desiredAmount - chosen.length;
        const rotated = [...processed.slice(needed), ...processed.slice(0, needed)];
        chosen.push(...rotated.slice(0, needed));
      }
    }

    this.state.used_games = [
      ...this.state.used_games.filter((gid) => !chosen.includes(gid)),
      ...chosen,
    ];
    const registry = new Map(this.catalog.map((i) => [i.title_id, i]));
    return chosen.map((id) => registry.get(id)).filter(Boolean);
  }

  async startHeadless(gamesCount = null, hours = null) {
    this.terminal.displayHeader();
    if (!this.state.token || !this.state.cookie) {
      const err = "Token and cf_clearance cookie are required (set in .env or session.json)";
      this.terminal.failure("auth", err);
      return { success: false, error: err };
    }

    this.terminal.log("loading detectable games catalog...");
    this.catalog = await loadGameCatalog();
    if (!this.catalog.length) {
      const err = "Unable to retrieve detectable games catalog.";
      this.terminal.failure("catalog", err);
      return { success: false, error: err };
    }
    this.terminal.success("catalog", `${this.catalog.length} verified titles loaded`);

    this.terminal.log("synchronizing analytics credentials...");
    await this.renewSession();
    try {
      await synchronizeCredentials(this.state, this.runtime_context.encoded_properties);
    } catch (exc) {
      this.terminal.failure("auth", String(exc.message || exc));
      return { success: false, error: String(exc.message || exc) };
    }
    this.terminal.success("auth", "Ingestion pipeline initialized");

    const targetCount = Math.min(
      gamesCount !== null ? gamesCount : this.catalog.length,
      this.catalog.length
    );
    const targetHours = hours !== null ? hours : 1.0;

    const selectedTitles = this.filterTitleSelection(targetCount);
    if (!selectedTitles.length) {
      const err = "No titles selected.";
      this.terminal.failure("catalog", err);
      return { success: false, error: err };
    }

    const durationMs = Math.floor(targetHours * 3600 * 1000);
    const totalAggregate = selectedTitles.length * targetHours;
    console.log();
    this.terminal.log(
      `Submitting ${TerminalInterface.COLOR_PRIMARY}${targetHours}h${TerminalInterface.COLOR_TEXT} across ` +
        `${TerminalInterface.COLOR_PRIMARY}${selectedTitles.length}${TerminalInterface.COLOR_TEXT} titles ` +
        `(${totalAggregate.toLocaleString()}h total)`
    );
    this.terminal.separator();

    const engine = new IngestionPipeline(this.fabricator, this.terminal);
    const accepted = await engine.executeStream(selectedTitles, (title) =>
      this.fabricator.assembleCompleteSession(title, durationMs)
    );

    console.log();
    this.terminal.success(
      "completed",
      `${accepted}/${selectedTitles.length} titles processed (${(accepted * targetHours).toLocaleString()}h total)`
    );
    this.state.total_games_claimed += accepted;
    this.state.total_hours_claimed += accepted * targetHours;
    this.state.persist();

    return {
      success: true,
      accepted,
      total_requested: selectedTitles.length,
      hours_per_game: targetHours,
      total_hours: accepted * targetHours,
    };
  }

  async start() {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const prompt = async (msg) => {
      try {
        return (await rl.question(msg)).trim();
      } catch {
        return "";
      }
    };

    try {
      this.terminal.displayHeader();
      await new Promise((r) => setTimeout(r, 300));

      if (!this.state.token) {
        this.terminal.log("Paste your Discord account authorization token:");
        const val = await prompt(`  ${TerminalInterface.COLOR_MUTED}token:${TerminalInterface.COLOR_RESET} `);
        if (val) {
          this.state.token = val;
          this.state.persist();
          this.terminal.success("token", "Saved to local state");
        }
      } else {
        this.terminal.success("auth", "User token loaded from state");
      }

      if (!this.state.token) {
        this.terminal.failure("token", "Account token is required.");
        rl.close();
        return;
      }

      if (!this.state.cookie) {
        this.terminal.log("Paste your cf_clearance cookie header value:");
        const val = await prompt(`  ${TerminalInterface.COLOR_MUTED}cookie:${TerminalInterface.COLOR_RESET} `);
        if (val) {
          this.state.cookie = val;
          this.state.persist();
          this.terminal.success("cookie", "Saved to local state");
        }
      } else {
        this.terminal.success("auth", "Clearance cookie loaded from state");
      }

      if (!this.state.cookie) {
        this.terminal.failure("cookie", "cf_clearance cookie is required.");
        rl.close();
        return;
      }

      this.terminal.log("loading detectable games catalog...");
      this.catalog = await loadGameCatalog();
      if (!this.catalog.length) {
        this.terminal.failure("catalog", "Unable to retrieve detectable games catalog.");
        rl.close();
        return;
      }
      this.terminal.success("catalog", `${this.catalog.length} verified titles loaded`);

      if (!this.state.fingerprint) {
        this.terminal.warning("fingerprint", "Executable fingerprint not set (optional for hours, recommended for variety).");
      }

      this.terminal.log("synchronizing analytics credentials...");
      await this.renewSession();
      try {
        await synchronizeCredentials(this.state, this.runtime_context.encoded_properties);
      } catch (exc) {
        this.terminal.failure("auth", String(exc.message || exc));
        rl.close();
        return;
      }
      this.terminal.success("auth", "Ingestion pipeline initialized");

      await new Promise((r) => setTimeout(r, 500));

      while (true) {
        this.terminal.clearViewport();
        this.terminal.displayHeader();
        this.terminal.log(
          `Detectable Titles: ${TerminalInterface.COLOR_PRIMARY}${this.catalog.length}${TerminalInterface.COLOR_TEXT}`
        );
        this.terminal.log(
          `Cumulative Logged: ${TerminalInterface.COLOR_PRIMARY}${this.state.total_games_claimed}${TerminalInterface.COLOR_TEXT} titles · ` +
            `${TerminalInterface.COLOR_PRIMARY}${this.state.total_hours_claimed.toLocaleString()}h${TerminalInterface.COLOR_TEXT} playtime`
        );
        this.terminal.separator();
        this.terminal.log(`${TerminalInterface.COLOR_PRIMARY}1${TerminalInterface.COLOR_RESET} · Claim Games (Game Time & Game Variety)`);
        this.terminal.log(`${TerminalInterface.COLOR_PRIMARY}2${TerminalInterface.COLOR_RESET} · Inspect Discord Profile & Badges`);
        this.terminal.log(`${TerminalInterface.COLOR_PRIMARY}3${TerminalInterface.COLOR_RESET} · Refresh Credentials & Cookie`);
        this.terminal.log(`${TerminalInterface.COLOR_PRIMARY}4${TerminalInterface.COLOR_RESET} · Configure Executable Fingerprint`);
        this.terminal.log(`${TerminalInterface.COLOR_PRIMARY}5${TerminalInterface.COLOR_RESET} · Exit`);
        this.terminal.separator();

        const selection = await prompt(`  ${TerminalInterface.COLOR_PRIMARY}›${TerminalInterface.COLOR_RESET} `);
        console.log();

        if (selection === "1") {
          const rawCount = await prompt(`  ${TerminalInterface.COLOR_MUTED}Target games count [all]:${TerminalInterface.COLOR_RESET} `);
          const targetCount = rawCount ? parseInt(rawCount, 10) : this.catalog.length;
          const rawHours = await prompt(`  ${TerminalInterface.COLOR_MUTED}Hours per game [1]:${TerminalInterface.COLOR_RESET} `);
          const targetHours = rawHours ? parseFloat(rawHours) : 1.0;

          await this.startHeadless(targetCount, targetHours);
          await prompt(`  ${TerminalInterface.COLOR_PRIMARY}›${TerminalInterface.COLOR_RESET} Press enter to return to menu`);
        } else if (selection === "2") {
          await this.inspectProfile();
          await prompt(`  ${TerminalInterface.COLOR_PRIMARY}›${TerminalInterface.COLOR_RESET} Press enter to continue`);
        } else if (selection === "3") {
          const ans = (await prompt(`  ${TerminalInterface.COLOR_MUTED}Update cookie header? [y/n] ›${TerminalInterface.COLOR_RESET} `)).toLowerCase();
          if (ans === "y" || ans === "yes") {
            const newCk = await prompt(`  ${TerminalInterface.COLOR_MUTED}cookie:${TerminalInterface.COLOR_RESET} `);
            if (newCk) {
              this.state.cookie = newCk;
              this.terminal.success("cookie", "Updated");
            }
          }
          this.state.fetched_at = 0;
          await this.renewSession();
          await synchronizeCredentials(this.state, this.runtime_context.encoded_properties);
          this.state.persist();
          this.terminal.success("auth", "Credentials refreshed successfully");
          await new Promise((r) => setTimeout(r, 1000));
        } else if (selection === "4") {
          await this.configureExecutableFingerprint(prompt);
        } else if (["5", "q", "exit", ""].includes(selection)) {
          break;
        } else {
          this.terminal.warning("input", "Invalid selection.");
          await new Promise((r) => setTimeout(r, 500));
        }
      }
    } finally {
      rl.close();
    }
  }

  async inspectProfile() {
    const T = this.terminal;
    if (!this.state.token) {
      T.failure("auth", "No user token configured.");
      return;
    }
    T.log("Retrieving profile data from Discord...");
    let uid = extractAccountSnowflake(this.state.token);
    const encodedProps = this.runtime_context ? this.runtime_context.encoded_properties : "";

    if (!uid) {
      try {
        const res = await fetch(REST_IDENTITY_URL, {
          headers: {
            authorization: this.state.token,
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-super-properties": encodedProps,
          },
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) {
          const me = await res.json();
          uid = me.id || "";
        }
      } catch {
        // Ignore
      }
    }

    if (!uid) {
      T.failure("profile", "Unable to resolve account identity snowflake.");
      return;
    }

    try {
      const res = await fetch(
        `${DISCORD_USERS_API}/${uid}/profile?with_mutual_guilds=false&with_mutual_friends_count=false`,
        {
          headers: {
            authorization: this.state.token,
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-super-properties": encodedProps,
          },
          signal: AbortSignal.timeout(15000),
        }
      );
      if (res.ok) {
        const data = await res.json();
        const userObj = data.user || {};
        const badgesList = data.badges || [];
        T.separator();
        const userHandle = userObj.username || "Unknown";
        const globalName = userObj.global_name;
        const displayName = globalName ? `${globalName} (@${userHandle})` : `@${userHandle}`;
        T.success("account", `${displayName} · ID: ${uid}`);

        if (badgesList.length) {
          T.log(`Profile Badges (${badgesList.length}):`);
          for (const badge of badgesList) {
            const bid = badge.id || "badge";
            const desc = badge.description || "";
            T.log(
              `  ${TerminalInterface.COLOR_PRIMARY}•${TerminalInterface.COLOR_RESET} ` +
                `${TerminalInterface.COLOR_TEXT}${bid}${TerminalInterface.COLOR_RESET}: ${desc}`
            );
          }
        } else {
          T.log("No public badges equipped on profile.");
        }
      } else {
        T.failure("profile", `HTTP ${res.status}`);
      }
    } catch (exc) {
      T.failure("profile", `Failed to retrieve profile: ${exc.message || exc}`);
    }
  }

  async configureExecutableFingerprint(prompt) {
    const T = this.terminal;
    const accountId = extractAccountSnowflake(this.state.token);
    if (!accountId) {
      T.failure("fingerprint", "Valid token required to derive user identity.");
      return;
    }
    if (process.platform !== "win32") {
      T.failure("fingerprint", "Fingerprint generation requires Windows OS.");
      return;
    }

    T.log("Generate executable fingerprint bound to account and machine.");
    T.log(`Account Snowflake: ${TerminalInterface.COLOR_PRIMARY}${accountId}${TerminalInterface.COLOR_RESET}`);
    T.log("Provide an executable (.exe) path or active game Process ID (PID):");
    const rawInput = (await prompt(`  ${TerminalInterface.COLOR_MUTED}path or PID:${TerminalInterface.COLOR_RESET} `)).replace(/^"|"$/g, "");
    if (!rawInput) {
      T.log("Operation cancelled.");
      return;
    }

    const targetPid = /^\d+$/.test(rawInput) ? parseInt(rawInput, 10) : 0;
    const targetPath = targetPid ? "" : rawInput;

    if (targetPath && !fs.existsSync(targetPath)) {
      T.failure("fingerprint", `File path does not exist: ${targetPath}`);
      return;
    }

    T.log("Generating signature via PowerShell PE analyzer...");
    try {
      const signature = buildBinarySignature(accountId, targetPath, targetPid);
      this.state.fingerprint = signature;
      this.state.persist();
      T.success("fingerprint", `Assigned (${signature.length} chars) · saved to state`);
    } catch (exc) {
      T.failure("fingerprint", String(exc.message || exc));
    }
  }
}

// Entrypoint
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  let gamesCount = null;
  let hours = null;
  let auto = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--games" && i + 1 < args.length) {
      gamesCount = parseInt(args[++i], 10);
    } else if (args[i] === "--hours" && i + 1 < args.length) {
      hours = parseFloat(args[++i]);
    } else if (args[i] === "--auto") {
      auto = true;
    }
  }

  const app = new ApplicationController();
  if (auto || gamesCount !== null || hours !== null) {
    app.startHeadless(gamesCount, hours).catch((err) => {
      console.error(err);
      process.exit(1);
    });
  } else {
    app.start().catch((err) => {
      console.error(err);
      process.exit(1);
    });
  }
}
