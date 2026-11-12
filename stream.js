#!/usr/bin/env node
/**
 * Discord Stream Time Engine (Node.js)
 *
 * Headless Gateway + Voice + Video Streamer + Go Live streamer that accumulates
 * real streaming hours for the Discord Streaming Badge.
 *
 * 1. Connects to Discord's main Gateway WebSocket (v9)
 * 2. Joins a voice channel (Opcode 4 Voice State Update)
 * 3. Completes Voice WebSocket (v7) + UDP IP Discovery handshake
 * 4. Initiates Go Live (Opcode 18 Stream Create)
 * 5. Connects to dedicated Voice Stream WebSocket
 * 6. Streams real H.264 video and Opus audio from local media / URL (or silent Opus audio fallback)
 * 7. Encrypts packets using AES-256-GCM (aead_aes256_gcm_rtpsize) and emits 1-second RTCP Sender Reports
 * 8. Automated Alt Viewer engine via Opcode 20 (STREAM_WATCH)
 * 9. Manages heartbeats and auto-reconnects across all WebSockets
 */

import crypto from "node:crypto";
import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline/promises";
import { spawn, execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import dotenv from "dotenv";
import WebSocket from "ws";
import { decryptToken, encryptToken } from "./crypto_vault.js";

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.dirname(__filename);
const STATE_FILE = path.join(ROOT, "session.json");

dotenv.config({ path: path.join(ROOT, ".env") });

export const ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true";
export const USERS_URL = "https://discord.com/api/v9/users";
export const SCIENCE_URL = "https://discord.com/api/v9/science";
export const PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows";
export const GATEWAY_URL = "gateway.discord.gg";

export const CLIENT_VERSION = "1.0.9253";
export const CLIENT_BUILD_NUMBER = 594031;
export const NATIVE_BUILD_NUMBER = 88414;
export const OS_VERSION = "10.0.26200";
export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 " +
  "Electron/42.7.1 Safari/537.36";

export const AUTH_MAX_AGE = 12 * 3600;
export const OPUS_SILENCE = Buffer.from([0xf8, 0xff, 0xfe]);

export const STREAM_TIERS = [
  [1, "Newcomer", 1],
  [2, "Fledgling", 5],
  [3, "Breakout", 20],
  [4, "Standout", 75],
  [5, "Trendsetter", 150],
  [6, "Headliner", 300],
  [7, "Star", 500],
  [8, "Sensation", 1000],
  [9, "Visionary", 2000],
  [10, "Phenomenon", 5000],
];

export function findFfmpegBinary() {
  const binaryName = process.platform === "win32" ? "ffmpeg.exe" : "ffmpeg";
  const commonDirs = [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    path.join(os.homedir(), ".local", "bin"),
    path.join(os.homedir(), "bin"),
  ];

  try {
    const whichCmd = process.platform === "win32" ? "where ffmpeg" : "which ffmpeg";
    const found = execSync(whichCmd, { stdio: ["ignore", "pipe", "ignore"], encoding: "utf8" }).trim();
    if (found) {
      return found.split(/\r?\n/)[0];
    }
  } catch {
    // Continue searching
  }

  for (const d of commonDirs) {
    const candidate = path.join(d, binaryName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  const localCandidate = path.join(ROOT, binaryName);
  if (fs.existsSync(localCandidate)) {
    return localCandidate;
  }

  return "ffmpeg";
}

export function userIdFromToken(token) {
  try {
    const first = String(token || "").split(".", 1)[0];
    const pad = "=".repeat((-first.length % 4 + 4) % 4);
    return Buffer.from(first + pad, "base64").toString("utf-8");
  } catch {
    return "";
  }
}

export function formatTimer(seconds) {
  const s = Math.floor(seconds || 0);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

export class Console {
  static RED = "\x1b[91m";
  static GREEN = "\x1b[92m";
  static YELLOW = "\x1b[93m";
  static CYAN = "\x1b[96m";
  static WHITE = "\x1b[97m";
  static GREY = "\x1b[90m";
  static MAGENTA = "\x1b[95m";
  static ORANGE = "\x1b[38;5;208m";
  static RESET = "\x1b[0m";

  constructor() {
    this.RED = Console.RED;
    this.GREEN = Console.GREEN;
    this.YELLOW = Console.YELLOW;
    this.CYAN = Console.CYAN;
    this.WHITE = Console.WHITE;
    this.GREY = Console.GREY;
    this.MAGENTA = Console.MAGENTA;
    this.ORANGE = Console.ORANGE;
    this.RESET = Console.RESET;
  }

  getTerminalWidth() {
    return process.stdout.columns || 80;
  }

  createBorder(char = "═") {
    const width = this.getTerminalWidth();
    return char.repeat(Math.max(10, width - 2));
  }

  stamp() {
    const d = new Date();
    const timeStr = [d.getHours(), d.getMinutes(), d.getSeconds()]
      .map((n) => String(n).padStart(2, "0"))
      .join(":");
    return `${this.GREY}${timeStr}${this.RESET}`;
  }

  line(glyph, target, detail, color) {
    console.log(
      `  ${this.stamp()} ${glyph} ${this.WHITE}${target}${this.RESET} ` +
        `${this.GREY}·${this.RESET} ${color}${detail}${this.RESET}`
    );
  }

  ok(target, detail) {
    this.line(`${this.GREEN}✓${this.RESET}`, target, detail, this.GREEN);
  }

  sent(target, detail) {
    this.line(`${this.GREY}·${this.RESET} ${this.GREEN}sent${this.RESET}`, target, detail, this.GREEN);
  }

  live(target, detail) {
    this.line(`${this.MAGENTA}● LIVE${this.RESET}`, target, detail, this.MAGENTA);
  }

  warn(target, detail) {
    this.line(`${this.YELLOW}!${this.RESET}`, target, detail, this.YELLOW);
  }

  err(target, detail) {
    this.line(`${this.RED}✗${this.RESET}`, target, detail, this.RED);
  }

  info(targetOrDetail, detail = "") {
    if (!detail) {
      console.log(`  ${this.stamp()} ${this.GREY}·${this.RESET} ${this.WHITE}${targetOrDetail}${this.RESET}`);
    } else {
      this.line(`${this.GREY}·${this.RESET}`, targetOrDetail, detail, this.WHITE);
    }
  }

  rule(char = "─", color = null) {
    const width = this.getTerminalWidth();
    const c = color || this.CYAN;
    console.log(`${c}${char.repeat(width)}${this.RESET}`);
  }

  clear() {
    process.stdout.write("\x1b[2J\x1b[3J\x1b[H");
  }

  banner() {
    this.clear();
    const width = this.getTerminalWidth();
    const border = this.createBorder("═");
    const title = "DISCORD BADGE MAXIMIZER";
    const subtitle = "Headless Streaming Badge Engine (Node.js)";

    const padT = " ".repeat(Math.max(0, Math.floor((width - title.length - 2) / 2)));
    const padTR = " ".repeat(Math.max(0, width - title.length - 2 - padT.length));
    const padS = " ".repeat(Math.max(0, Math.floor((width - subtitle.length - 2) / 2)));
    const padSR = " ".repeat(Math.max(0, width - subtitle.length - 2 - padS.length));

    console.log();
    console.log(`${this.CYAN}╔${border}╗${this.RESET}`);
    console.log(
      `${this.CYAN}║${this.RESET}${padT}${this.WHITE}${title}${this.RESET}${padTR}${this.CYAN}║${this.RESET}`
    );
    console.log(
      `${this.CYAN}║${this.RESET}${padS}${this.GREY}${subtitle}${this.RESET}${padSR}${this.CYAN}║${this.RESET}`
    );
    console.log(`${this.CYAN}╚${border}╝${this.RESET}`);
    console.log();
  }
}

export class State {
  constructor(data = {}) {
    this.token = data.token || "";
    this.viewer_token = data.viewer_token || "";
    this.cookie = data.cookie || "";
    this.analytics_token = data.analytics_token || "";
    this.fetched_at = data.fetched_at || 0;
    this.last_guild_id = data.last_guild_id || "";
    this.last_channel_id = data.last_channel_id || "";
    this.stream_url = data.stream_url || "";
    this.total_stream_hours_claimed = data.total_stream_hours_claimed || 0.0;
    this.total_stream_sessions = data.total_stream_sessions || 0;
    this._filepath = data._filepath || null;
  }

  static load(customPath = null) {
    const target = customPath || STATE_FILE;
    const instance = new State({ _filepath: target });

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
        instance.viewer_token = decryptToken(instance.viewer_token, uidStr);
        instance.cookie = decryptToken(instance.cookie, uidStr);
      } catch {
        // Ignore read errors
      }
    }

    if (!customPath) {
      if (!instance.token && process.env.DISCORD_TOKEN) {
        instance.token = process.env.DISCORD_TOKEN.trim();
      }
      if (!instance.viewer_token && process.env.DISCORD_VIEWER_TOKEN) {
        instance.viewer_token = process.env.DISCORD_VIEWER_TOKEN.trim();
      }
      if (!instance.cookie && process.env.DISCORD_COOKIE) {
        instance.cookie = process.env.DISCORD_COOKIE.trim();
      }
      if (!instance.last_channel_id && process.env.VOICE_CHANNEL_ID) {
        instance.last_channel_id = process.env.VOICE_CHANNEL_ID.trim();
      }
      if (!instance.stream_url && process.env.STREAM_URL) {
        instance.stream_url = process.env.STREAM_URL.trim();
      }
    }

    return instance;
  }

  save(customPath = null) {
    const target = customPath || this._filepath || STATE_FILE;
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
      viewer_token: this.viewer_token,
      cookie: this.cookie,
      analytics_token: this.analytics_token,
      fetched_at: this.fetched_at,
      last_guild_id: this.last_guild_id,
      last_channel_id: this.last_channel_id,
      stream_url: this.stream_url,
      total_stream_hours_claimed: this.total_stream_hours_claimed,
      total_stream_sessions: this.total_stream_sessions,
    };

    const uidStr =
      target && path.parse(target).name && /^\d+$/.test(path.parse(target).name)
        ? path.parse(target).name
        : "";
    if (saveData.token) saveData.token = encryptToken(saveData.token, uidStr);
    if (saveData.viewer_token) saveData.viewer_token = encryptToken(saveData.viewer_token, uidStr);
    if (saveData.cookie) saveData.cookie = encryptToken(saveData.cookie, uidStr);

    Object.assign(existing, saveData);
    fs.writeFileSync(target, JSON.stringify(existing, null, 2), "utf8");
  }

  get isStale() {
    return !this.analytics_token || Date.now() / 1000 - this.fetched_at > AUTH_MAX_AGE;
  }

  get hasToken() {
    return Boolean(this.token.trim());
  }

  get hasViewerToken() {
    return Boolean(this.viewer_token.trim());
  }

  get hasCookie() {
    return Boolean(this.cookie.trim());
  }
}

export function localProps() {
  return {
    os: "Windows",
    browser: "Discord Client",
    release_channel: "stable",
    client_version: CLIENT_VERSION,
    os_version: OS_VERSION,
    os_arch: "x64",
    app_arch: "x64",
    system_locale: "en-US",
    has_client_mods: false,
    browser_user_agent: USER_AGENT,
    browser_version: "42.7.1",
    os_sdk_version: "26200",
    client_build_number: CLIENT_BUILD_NUMBER,
    native_build_number: NATIVE_BUILD_NUMBER,
    client_event_source: null,
    client_app_state: "focused",
  };
}

export async function buildSuperProps(launchSignature, heartbeatSession) {
  let props;
  try {
    const res = await fetch(PROPERTIES_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: "{}",
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const data = await res.json();
      props = data.properties;
    }
  } catch {
    // Ignore
  }

  if (!props) {
    props = localProps();
  }

  props.client_launch_id = crypto.randomUUID();
  props.launch_signature = launchSignature;
  props.client_heartbeat_session_id = heartbeatSession;

  const raw = Buffer.from(JSON.stringify(props), "utf8");
  return { b64: raw.toString("base64"), props };
}

export class Session {
  constructor(heartbeatSession, launchSignature, superProps, superPropsDict) {
    this.heartbeat_session = heartbeatSession;
    this.launch_signature = launchSignature;
    this.super_props = superProps;
    this.super_props_dict = superPropsDict;
  }

  static async new() {
    const hb = crypto.randomUUID();
    const lsig = crypto.randomUUID();
    const { b64, props } = await buildSuperProps(lsig, hb);
    return new Session(hb, lsig, b64, props);
  }
}

export async function readAnalyticsToken(authToken, superProps) {
  const res = await fetch(ME_URL, {
    headers: {
      authorization: authToken,
      "user-agent": USER_AGENT,
      "x-super-properties": superProps,
    },
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`Token rejected (HTTP ${res.status})`);
  }

  const data = await res.json();
  const token = data.analytics_token;
  if (!token) {
    throw new Error("No analytics_token returned by Discord");
  }
  return token;
}

export async function ensureToken(state, superProps) {
  if (!state.isStale) return;
  state.analytics_token = await readAnalyticsToken(state.token, superProps);
  state.fetched_at = Math.floor(Date.now() / 1000);
  state.save();
}

export function resolveMediaSource(sourceUrlOrPath, consoleObj = null) {
  const src = (sourceUrlOrPath || "").trim();
  const defaultVideo = path.join(ROOT, "assets", "video.mp4");

  if (!src) {
    return fs.existsSync(defaultVideo) ? defaultVideo : "";
  }

  if (fs.existsSync(src)) {
    return src;
  }

  if (src.includes("youtube.com") || src.includes("youtu.be")) {
    try {
      if (consoleObj) {
        consoleObj.info("youtube", `extracting live stream URL from ${src}...`);
      }
      const streamUrl = execSync(
        `yt-dlp -g -f "best[ext=mp4]/best" --no-warnings --no-playlist "${src}"`,
        { encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
      if (streamUrl) {
        if (consoleObj) {
          consoleObj.ok("youtube", `resolved stream URL via yt-dlp`);
        }
        return streamUrl.split(/\r?\n/)[0];
      }
    } catch {
      if (consoleObj) {
        consoleObj.warn("youtube", "yt-dlp extraction failed, falling back to default video");
      }
      return fs.existsSync(defaultVideo) ? defaultVideo : src;
    }
  }

  if (src.startsWith("http://") || src.startsWith("https://")) {
    return src;
  }

  return fs.existsSync(defaultVideo) ? defaultVideo : "";
}

/**
 * MediaStreamPump handles spawning FFmpeg for H.264 video and Opus audio,
 * RTP packetizing, AES-256-GCM encryption, and RTCP Sender Reports.
 */
export class MediaStreamPump {
  constructor(voiceConn, videoPath, consoleObj) {
    this.conn = voiceConn;
    this.video_path = videoPath;
    this.console = consoleObj;
    this.running = false;
    this.v_proc = null;
    this.a_proc = null;
    this.is_url = this.video_path.startsWith("http://") || this.video_path.startsWith("https://");
  }

  sendRtcpSr(cipherKey, ssrc, rtpTs, pktCount, byteCount) {
    const nowWall = Date.now() / 1000;
    const ntpNow = nowWall + 2208988800.0;
    const ntpMsw = Math.floor(ntpNow);
    const ntpLsw = Math.floor((ntpNow - ntpMsw) * 0x100000000) >>> 0;

    const header = Buffer.alloc(8);
    header.writeUInt8(0x80, 0); // V=2, P=0, RC=0
    header.writeUInt8(200, 1);  // Payload type = 200 (SR)
    header.writeUInt16BE(6, 2); // Length in 32-bit words - 1 = 6
    header.writeUInt32BE(ssrc, 4);

    const payload = Buffer.alloc(20);
    payload.writeUInt32BE(ntpMsw, 0);
    payload.writeUInt32BE(ntpLsw, 4);
    payload.writeUInt32BE(rtpTs >>> 0, 8);
    payload.writeUInt32BE(pktCount >>> 0, 12);
    payload.writeUInt32BE(byteCount >>> 0, 16);

    const cnt = ++this.conn.nonce_counter;
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(cnt, 0);

    const cipher = crypto.createCipheriv("aes-256-gcm", cipherKey, nonce, { authTagLength: 16 });
    cipher.setAAD(header);
    const enc = cipher.update(payload);
    const finalEnc = cipher.final();
    const tag = cipher.getAuthTag();

    const cntBuf = Buffer.alloc(4);
    cntBuf.writeUInt32BE(cnt, 0);

    const rtcpPacket = Buffer.concat([header, enc, finalEnc, tag, cntBuf]);
    try {
      if (this.conn.udp_sock && this.conn.voice_ip && this.conn.voice_port) {
        this.conn.udp_sock.send(rtcpPacket, this.conn.voice_port, this.conn.voice_ip);
      }
    } catch {
      // Ignore socket send errors
    }
  }

  spawnVideo() {
    try {
      const ffmpegBin = findFfmpegBinary();
      const vInput = ["-stream_loop", "-1"];
      if (this.is_url) {
        vInput.push(
          "-reconnect", "1",
          "-reconnect_at_eof", "1",
          "-reconnect_streamed", "1",
          "-reconnect_delay_max", "5"
        );
      }

      const vArgs = [
        "-hide_banner", "-loglevel", "error",
        ...vInput,
        "-i", this.video_path,
        "-r", "30",
        "-vf", "scale=848:480",
        "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
        "-threads", "1",
        "-b:v", "1200k", "-maxrate", "1200k", "-bufsize", "2400k",
        "-g", "30", "-keyint_min", "30", "-sc_threshold", "0",
        "-bf", "0", "-b_strategy", "0", "-flags", "+low_delay",
        "-force_key_frames", "expr:gte(t,n_forced*1)",
        "-profile:v", "baseline", "-level", "3.1",
        "-x264opts", "b-pyramid=0:bframes=0:ref=1:no-scenecut=1:keyint=30:min-keyint=30:repeat-headers=1",
        "-pix_fmt", "yuv420p",
        "-bsf:v", "h264_mp4toannexb,dump_extra=freq=keyframe,h264_metadata=aud=insert",
        "-an", "-f", "h264", "pipe:1",
      ];

      return spawn(ffmpegBin, vArgs, { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
    } catch (exc) {
      this.console.err("stream", `failed to spawn ffmpeg video process: ${exc.message || exc}`);
      return null;
    }
  }

  spawnAudio() {
    try {
      const ffmpegBin = findFfmpegBinary();
      const aInput = ["-stream_loop", "-1"];
      if (this.is_url) {
        aInput.push(
          "-reconnect", "1",
          "-reconnect_at_eof", "1",
          "-reconnect_streamed", "1",
          "-reconnect_delay_max", "5"
        );
      }

      const aArgs = [
        "-hide_banner", "-loglevel", "error",
        ...aInput,
        "-i", this.video_path,
        "-vn", "-c:a", "libopus", "-ar", "48000", "-ac", "2", "-b:a", "64k",
        "-frame_duration", "20",
        "-f", "opus", "pipe:1",
      ];

      return spawn(ffmpegBin, aArgs, { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
    } catch (exc) {
      this.console.err("stream", `failed to spawn ffmpeg audio process: ${exc.message || exc}`);
      return null;
    }
  }

  start() {
    if (!this.is_url && !fs.existsSync(this.video_path)) {
      this.console.warn("stream", `video file not found at ${this.video_path}, falling back to silence`);
      return false;
    }
    if (!this.conn.secret_key || !this.conn.udp_sock) {
      this.console.warn("stream", "encryption key or udp socket missing, falling back to silence");
      return false;
    }

    try {
      this.running = true;
      this.v_proc = this.spawnVideo();
      this.a_proc = this.spawnAudio();

      if (!this.v_proc && !this.a_proc) {
        this.stop();
        return false;
      }

      if (this.v_proc) {
        this.pumpVideo();
      }
      if (this.a_proc) {
        this.pumpAudio();
      }

      const srcLabel = this.is_url ? this.video_path : path.basename(this.video_path);
      this.console.ok("stream", `transmitting real video and audio from ${srcLabel} (loop enabled)`);
      return true;
    } catch (exc) {
      this.console.err("stream", `failed to start ffmpeg pump: ${exc.message || exc}`);
      this.stop();
      return false;
    }
  }

  pumpVideo() {
    const cipherKey = this.conn.secret_key.subarray(0, 32);
    let vSeq = Math.floor(Math.random() * 0x7fff);
    let vTs = Math.floor(Math.random() * 0x7fffffff);
    const videoSsrc = this.conn.video_ssrc || (this.conn.ssrc + 1);

    let vPkts = 0;
    let vBytes = 0;
    let lastSr = Date.now();
    let buf = Buffer.alloc(0);

    const sendFrame = (nalus) => {
      if (!nalus.length || !this.running) return;

      for (let nIdx = 0; nIdx < nalus.length; nIdx++) {
        const data = nalus[nIdx];
        const isLastNalu = nIdx === nalus.length - 1;
        const hdr = data[0];
        const ntype = hdr & 0x1f;

        if (data.length <= 1100) {
          const marker = isLastNalu ? 0x80 : 0x00;
          const rtpHdr = Buffer.alloc(12);
          rtpHdr.writeUInt8(0x90, 0); // V=2, P=0, X=1 (extension)
          rtpHdr.writeUInt8(marker | 101, 1); // payload type 101
          rtpHdr.writeUInt16BE(vSeq & 0xffff, 2);
          rtpHdr.writeUInt32BE(vTs >>> 0, 4);
          rtpHdr.writeUInt32BE(videoSsrc, 8);

          const extHdr = Buffer.from([0xbe, 0xde, 0x00, 0x01]);
          const packetHeader = Buffer.concat([rtpHdr, extHdr]);
          const plaintext = Buffer.concat([Buffer.from([0x51, 0x00, 0x00, 0x00]), data]);

          const cnt = ++this.conn.nonce_counter;
          const nonce = Buffer.alloc(12);
          nonce.writeUInt32BE(cnt, 0);

          const cipher = crypto.createCipheriv("aes-256-gcm", cipherKey, nonce, { authTagLength: 16 });
          cipher.setAAD(packetHeader);
          const enc = cipher.update(plaintext);
          const finalEnc = cipher.final();
          const tag = cipher.getAuthTag();

          const cntBuf = Buffer.alloc(4);
          cntBuf.writeUInt32BE(cnt, 0);

          const packet = Buffer.concat([packetHeader, enc, finalEnc, tag, cntBuf]);
          try {
            this.conn.udp_sock.send(packet, this.conn.voice_port, this.conn.voice_ip);
            vPkts++;
            vBytes += packet.length;
          } catch {
            // Ignore
          }
          vSeq = (vSeq + 1) & 0xffff;
        } else {
          // FU-A fragmentation
          const fnri = hdr & 0xe0;
          const fuInd = fnri | 28;
          const body = data.subarray(1);
          const csize = 1100;
          const totalChunks = Math.ceil(body.length / csize);

          for (let idx = 0; idx < totalChunks; idx++) {
            const c = body.subarray(idx * csize, (idx + 1) * csize);
            let fuHdr;
            if (idx === 0) {
              fuHdr = 0x80 | ntype;
            } else if (idx === totalChunks - 1) {
              fuHdr = 0x40 | ntype;
            } else {
              fuHdr = ntype;
            }

            const fuPayload = Buffer.concat([Buffer.from([fuInd, fuHdr]), c]);
            const isLastPacket = isLastNalu && idx === totalChunks - 1;
            const marker = isLastPacket ? 0x80 : 0x00;

            const rtpHdr = Buffer.alloc(12);
            rtpHdr.writeUInt8(0x90, 0);
            rtpHdr.writeUInt8(marker | 101, 1);
            rtpHdr.writeUInt16BE(vSeq & 0xffff, 2);
            rtpHdr.writeUInt32BE(vTs >>> 0, 4);
            rtpHdr.writeUInt32BE(videoSsrc, 8);

            const extHdr = Buffer.from([0xbe, 0xde, 0x00, 0x01]);
            const packetHeader = Buffer.concat([rtpHdr, extHdr]);
            const plaintext = Buffer.concat([Buffer.from([0x51, 0x00, 0x00, 0x00]), fuPayload]);

            const cnt = ++this.conn.nonce_counter;
            const nonce = Buffer.alloc(12);
            nonce.writeUInt32BE(cnt, 0);

            const cipher = crypto.createCipheriv("aes-256-gcm", cipherKey, nonce, { authTagLength: 16 });
            cipher.setAAD(packetHeader);
            const enc = cipher.update(plaintext);
            const finalEnc = cipher.final();
            const tag = cipher.getAuthTag();

            const cntBuf = Buffer.alloc(4);
            cntBuf.writeUInt32BE(cnt, 0);

            const packet = Buffer.concat([packetHeader, enc, finalEnc, tag, cntBuf]);
            try {
              this.conn.udp_sock.send(packet, this.conn.voice_port, this.conn.voice_ip);
              vPkts++;
              vBytes += packet.length;
            } catch {
              // Ignore
            }
            vSeq = (vSeq + 1) & 0xffff;
          }
        }
      }

      vTs = (vTs + 3000) >>> 0;
      const now = Date.now();
      if (now - lastSr >= 1000) {
        this.sendRtcpSr(cipherKey, videoSsrc, vTs, vPkts, vBytes);
        lastSr = now;
      }
    };

    let curFrame = [];
    this.v_proc.stdout.on("data", (chunk) => {
      if (!this.running) return;
      buf = Buffer.concat([buf, chunk]);

      while (true) {
        let p4 = buf.indexOf(Buffer.from([0x00, 0x00, 0x00, 0x01]), 4);
        let p3 = buf.indexOf(Buffer.from([0x00, 0x00, 0x01]), 3);

        let nextP = -1;
        if (p4 !== -1 && p3 !== -1) {
          nextP = Math.min(p4, p3);
        } else if (p4 !== -1) {
          nextP = p4;
        } else if (p3 !== -1) {
          nextP = p3;
        }

        if (nextP === -1) break;

        const nal = buf.subarray(0, nextP);
        buf = buf.subarray(nextP);
        const sc = nal.slice(0, 4).equals(Buffer.from([0x00, 0x00, 0x00, 0x01])) ? 4 : 3;
        const naluBody = nal.subarray(sc);

        if (naluBody.length) {
          const ntype = naluBody[0] & 0x1f;
          if (ntype === 9) { // Access unit delimiter
            if (curFrame.length) {
              sendFrame(curFrame);
              curFrame = [];
            }
          }
          curFrame.push(naluBody);
        }
      }
    });

    this.v_proc.on("close", () => {
      if (this.running) {
        this.v_proc = this.spawnVideo();
        if (this.v_proc) this.pumpVideo();
      }
    });
  }

  pumpAudio() {
    const cipherKey = this.conn.secret_key.subarray(0, 32);
    let aSeq = Math.floor(Math.random() * 0x7fff);
    let aTs = Math.floor(Math.random() * 0x7fffffff);

    let aPkts = 0;
    let aBytes = 0;
    let lastASr = Date.now();
    let buf = Buffer.alloc(0);

    this.a_proc.stdout.on("data", (chunk) => {
      if (!this.running) return;
      buf = Buffer.concat([buf, chunk]);

      while (buf.length >= 27) {
        if (!buf.slice(0, 4).equals(Buffer.from("OggS"))) {
          const idx = buf.indexOf("OggS");
          if (idx === -1) {
            buf = Buffer.alloc(0);
            break;
          }
          buf = buf.subarray(idx);
          if (buf.length < 27) break;
        }

        const nSegs = buf[26];
        if (buf.length < 27 + nSegs) break;

        const segTable = buf.subarray(27, 27 + nSegs);
        let bodyLen = 0;
        for (let i = 0; i < nSegs; i++) bodyLen += segTable[i];

        if (buf.length < 27 + nSegs + bodyLen) break;

        const body = buf.subarray(27 + nSegs, 27 + nSegs + bodyLen);
        buf = buf.subarray(27 + nSegs + bodyLen);

        let offset = 0;
        let curPkt = Buffer.alloc(0);
        for (let i = 0; i < nSegs; i++) {
          const s = segTable[i];
          curPkt = Buffer.concat([curPkt, body.subarray(offset, offset + s)]);
          offset += s;

          if (s < 255) {
            const p = curPkt;
            curPkt = Buffer.alloc(0);

            if (p.slice(0, 8).equals(Buffer.from("OpusHead")) || p.slice(0, 8).equals(Buffer.from("OpusTags"))) {
              continue;
            }

            const rtpHdr = Buffer.alloc(12);
            rtpHdr.writeUInt8(0x80, 0);
            rtpHdr.writeUInt8(120, 1); // Opus payload type = 120
            rtpHdr.writeUInt16BE(aSeq & 0xffff, 2);
            rtpHdr.writeUInt32BE(aTs >>> 0, 4);
            rtpHdr.writeUInt32BE(this.conn.ssrc, 8);

            const cnt = ++this.conn.nonce_counter;
            const nonce = Buffer.alloc(12);
            nonce.writeUInt32BE(cnt, 0);

            const cipher = crypto.createCipheriv("aes-256-gcm", cipherKey, nonce, { authTagLength: 16 });
            cipher.setAAD(rtpHdr);
            const enc = cipher.update(p);
            const finalEnc = cipher.final();
            const tag = cipher.getAuthTag();

            const cntBuf = Buffer.alloc(4);
            cntBuf.writeUInt32BE(cnt, 0);

            const packet = Buffer.concat([rtpHdr, enc, finalEnc, tag, cntBuf]);
            try {
              this.conn.udp_sock.send(packet, this.conn.voice_port, this.conn.voice_ip);
              aPkts++;
              aBytes += packet.length;
            } catch {
              // Ignore
            }

            aSeq = (aSeq + 1) & 0xffff;
            aTs = (aTs + 960) >>> 0;

            const now = Date.now();
            if (now - lastASr >= 1000) {
              this.sendRtcpSr(cipherKey, this.conn.ssrc, aTs, aPkts, aBytes);
              lastASr = now;
            }
          }
        }
      }
    });

    this.a_proc.on("close", () => {
      if (this.running) {
        this.a_proc = this.spawnAudio();
        if (this.a_proc) this.pumpAudio();
      }
    });
  }

  stop() {
    this.running = false;
    if (this.v_proc) {
      try {
        this.v_proc.kill();
      } catch {
        // Ignore
      }
      this.v_proc = null;
    }
    if (this.a_proc) {
      try {
        this.a_proc.kill();
      } catch {
        // Ignore
      }
      this.a_proc = null;
    }
  }
}

/**
 * VoiceConnection handles Discord Voice Gateway v7/v8 and UDP RTP streaming.
 */
export class VoiceConnection {
  constructor(options) {
    this.endpoint = options.endpoint.replace(/:443$/, "");
    this.host = this.endpoint.split(":")[0];
    this.port = 443;
    this.server_id = options.server_id;
    this.user_id = options.user_id;
    this.session_id = options.session_id;
    this.token = options.token;
    this.console = options.console;
    this.label = options.label || "voice";
    this.is_stream = options.is_stream || false;
    this.stream_key = options.stream_key || "";
    this.channel_id = options.channel_id || "";

    this.ws = null;
    this.udp_sock = null;
    this.heartbeat_interval = 41.25;
    this.heartbeat_timer = null;
    this.running = false;

    this.ssrc = 0;
    this.video_ssrc = 0;
    this.rtx_ssrc = 0;
    this.voice_ip = "";
    this.voice_port = 0;
    this.external_ip = "";
    this.external_port = 0;
    this.secret_key = null;
    this.encryption_mode = "aead_aes256_gcm_rtpsize";
    this.nonce_counter = 0;

    this.media_pump = null;
    this.silence_timer = null;
  }

  connect() {
    return new Promise((resolve) => {
      const C = this.console;
      const wsUrl = `wss://${this.host}/?v=7`;

      try {
        this.ws = new WebSocket(wsUrl);
      } catch (exc) {
        C.err(this.label, `ws init failed: ${exc.message || exc}`);
        return resolve(false);
      }

      let resolved = false;
      const safeResolve = (val) => {
        if (!resolved) {
          resolved = true;
          resolve(val);
        }
      };

      const timeout = setTimeout(() => {
        C.err(this.label, "voice ws connection timeout");
        safeResolve(false);
      }, 15000);

      this.ws.on("open", () => {
        // Connected, waiting for Op 8 Hello
      });

      this.ws.on("message", async (data) => {
        try {
          const msg = JSON.parse(data.toString("utf8"));
          const op = msg.op;
          const d = msg.d || {};

          if (op === 8) {
            // Hello
            this.heartbeat_interval = (d.heartbeat_interval || 13750) / 1000;
            const identifyD = {
              server_id: this.server_id,
              user_id: this.user_id,
              session_id: this.session_id,
              token: this.token,
              max_dave_protocol_version: 0,
            };
            if (this.is_stream) {
              if (this.stream_key) identifyD.stream_key = this.stream_key;
              identifyD.video = true;
              identifyD.streams = [{ type: "screen", rid: "100", quality: 100 }];
            }
            this.ws.send(JSON.stringify({ op: 0, d: identifyD }));
          } else if (op === 2) {
            // Ready
            this.ssrc = d.ssrc || 0;
            const streams = d.streams || [];
            if (streams.length > 0) {
              this.video_ssrc = streams[0].ssrc || this.ssrc + 1;
              this.rtx_ssrc = streams[0].rtx_ssrc || this.video_ssrc + 1;
            } else {
              this.video_ssrc = this.ssrc + 1;
              this.rtx_ssrc = this.ssrc + 2;
            }

            this.voice_ip = d.ip || "";
            this.voice_port = d.port || 0;
            const modes = d.modes || [];

            const preferred = [
              "aead_aes256_gcm_rtpsize",
              "aead_xchacha20_poly1305_rtpsize",
              "xsalsa20_poly1305_lite",
              "xsalsa20_poly1305",
            ];
            for (const mode of preferred) {
              if (modes.includes(mode)) {
                this.encryption_mode = mode;
                break;
              }
            }

            await this.performUdpDiscovery();

            const codecs = [
              { name: "opus", type: "audio", priority: 1000, payload_type: 120 },
            ];
            if (this.is_stream) {
              codecs.push(
                { name: "H264", type: "video", priority: 1000, payload_type: 101, rtx_payload_type: 102, encode: true, decode: true },
                { name: "VP8", type: "video", priority: 2000, payload_type: 103, rtx_payload_type: 104, encode: true, decode: true }
              );
            }

            this.ws.send(
              JSON.stringify({
                op: 1,
                d: {
                  protocol: "udp",
                  data: {
                    address: this.external_ip,
                    port: this.external_port,
                    mode: this.encryption_mode,
                  },
                  codecs,
                },
              })
            );
          } else if (op === 4) {
            // Session Description
            clearTimeout(timeout);
            this.secret_key = Buffer.from(d.secret_key || []);
            this.encryption_mode = d.mode || this.encryption_mode;
            const aCodec = d.audio_codec || "opus";
            const vCodec = d.video_codec || "none";
            C.ok(this.label, `media route ready (audio=${aCodec}, video=${vCodec}, mode=${this.encryption_mode})`);
            this.running = true;
            safeResolve(true);
          }
        } catch {
          // Ignore parse errors
        }
      });

      this.ws.on("error", (err) => {
        C.err(this.label, `ws error: ${err.message || err}`);
        safeResolve(false);
      });

      this.ws.on("close", () => {
        this.running = false;
        safeResolve(false);
      });
    });
  }

  performUdpDiscovery() {
    return new Promise((resolve) => {
      try {
        this.udp_sock = dgram.createSocket("udp4");
        this.udp_sock.bind(() => {
          const packet = Buffer.alloc(74);
          packet.writeUInt16BE(1, 0); // Type 1: Request
          packet.writeUInt16BE(70, 2); // Length 70
          packet.writeUInt32BE(this.ssrc, 4);

          const timeout = setTimeout(() => {
            this.external_ip = "127.0.0.1";
            this.external_port = 10000 + Math.floor(Math.random() * 50000);
            resolve(false);
          }, 3000);

          this.udp_sock.once("message", (msg) => {
            clearTimeout(timeout);
            try {
              if (msg.length >= 74) {
                const ipEnd = msg.indexOf(0, 8);
                this.external_ip = msg.toString("utf8", 8, ipEnd !== -1 ? ipEnd : 72);
                this.external_port = msg.readUInt16BE(72);
                return resolve(true);
              }
            } catch {
              // Ignore
            }
            this.external_ip = "127.0.0.1";
            this.external_port = 10000 + Math.floor(Math.random() * 50000);
            resolve(false);
          });

          this.udp_sock.send(packet, this.voice_port, this.voice_ip);
        });
      } catch {
        this.external_ip = "127.0.0.1";
        this.external_port = 10000 + Math.floor(Math.random() * 50000);
        resolve(false);
      }
    });
  }

  startHeartbeat() {
    if (this.heartbeat_timer) clearInterval(this.heartbeat_timer);
    this.heartbeat_timer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ op: 3, d: Math.floor(Date.now() / 1000) }));
      }
    }, this.heartbeat_interval * 1000);
  }

  sendSpeaking(speaking = true, isVideo = true) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const flags = speaking ? (isVideo ? 3 : 1) : 0;
    this.ws.send(
      JSON.stringify({
        op: 5,
        d: { speaking: flags, delay: 0, ssrc: this.ssrc },
      })
    );
  }

  startMediaStream(videoPath) {
    this.stopSilencePump();
    this.media_pump = new MediaStreamPump(this, videoPath, this.console);
    return this.media_pump.start();
  }

  stopMediaStream() {
    if (this.media_pump) {
      this.media_pump.stop();
      this.media_pump = null;
    }
  }

  startSilencePump() {
    if (this.silence_timer) return;
    let seq = Math.floor(Math.random() * 0x7fff);
    let ts = Math.floor(Math.random() * 0x7fffffff);
    const cipherKey = this.secret_key ? this.secret_key.subarray(0, 32) : null;
    if (!cipherKey) return;

    this.silence_timer = setInterval(() => {
      if (!this.running || !this.udp_sock || !this.voice_ip || !this.voice_port) return;

      const rtpHdr = Buffer.alloc(12);
      rtpHdr.writeUInt8(0x80, 0);
      rtpHdr.writeUInt8(120, 1);
      rtpHdr.writeUInt16BE(seq & 0xffff, 2);
      rtpHdr.writeUInt32BE(ts >>> 0, 4);
      rtpHdr.writeUInt32BE(this.ssrc, 8);

      const cnt = ++this.nonce_counter;
      const nonce = Buffer.alloc(12);
      nonce.writeUInt32BE(cnt, 0);

      const cipher = crypto.createCipheriv("aes-256-gcm", cipherKey, nonce, { authTagLength: 16 });
      cipher.setAAD(rtpHdr);
      const enc = cipher.update(OPUS_SILENCE);
      const finalEnc = cipher.final();
      const tag = cipher.getAuthTag();

      const cntBuf = Buffer.alloc(4);
      cntBuf.writeUInt32BE(cnt, 0);

      const packet = Buffer.concat([rtpHdr, enc, finalEnc, tag, cntBuf]);
      try {
        this.udp_sock.send(packet, this.voice_port, this.voice_ip);
      } catch {
        // Ignore
      }

      seq = (seq + 1) & 0xffff;
      ts = (ts + 960) >>> 0;
    }, 20);
  }

  stopSilencePump() {
    if (this.silence_timer) {
      clearInterval(this.silence_timer);
      this.silence_timer = null;
    }
  }

  close() {
    this.running = false;
    this.stopSilencePump();
    this.stopMediaStream();
    if (this.heartbeat_timer) {
      clearInterval(this.heartbeat_timer);
      this.heartbeat_timer = null;
    }
    if (this.udp_sock) {
      try {
        this.udp_sock.close();
      } catch {
        // Ignore
      }
      this.udp_sock = null;
    }
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // Ignore
      }
      this.ws = null;
    }
  }
}

/**
 * ViewerEngine connects an alt account to Discord Gateway to watch the Go Live stream
 * via Opcode 20 STREAM_WATCH, ensuring Discord counts stream hours.
 */
export class ViewerEngine {
  constructor(token, consoleObj) {
    this.token = token.trim();
    this.console = consoleObj;
    this.ws = null;
    this.running = false;
    this.guild_id = "";
    this.channel_id = "";
    this.stream_key = "";
    this.user_id = "";
    this.username = "";
    this.heartbeat_interval = 41.25;
    this.sequence = null;
    this.is_watching = false;
    this.hb_timer = null;
  }

  start(guildId, channelId) {
    this.guild_id = guildId;
    this.channel_id = channelId;
    this.running = true;
    this.run();
  }

  watch(streamKey) {
    this.stream_key = streamKey;
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(JSON.stringify({ op: 20, d: { stream_key: streamKey } }));
      if (!this.is_watching) {
        this.is_watching = true;
        this.console.ok("viewer", `alt account (${this.username || "alt"}) watching stream via Opcode 20 STREAM_WATCH`);
      }
    } catch {
      // Ignore
    }
  }

  run() {
    if (!this.running) return;
    const wsUrl = `wss://${GATEWAY_URL}/?v=9&encoding=json`;

    try {
      this.ws = new WebSocket(wsUrl);
    } catch {
      if (this.running) setTimeout(() => this.run(), 3000);
      return;
    }

    this.ws.on("message", (raw) => {
      try {
        const msg = JSON.parse(raw.toString("utf8"));
        const { op, s, t, d } = msg;

        if (s !== null && s !== undefined) {
          this.sequence = s;
        }

        if (op === 10) {
          // Hello
          this.heartbeat_interval = (d.heartbeat_interval || 41250) / 1000;
          if (this.hb_timer) clearInterval(this.hb_timer);
          this.hb_timer = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
            }
          }, this.heartbeat_interval * 1000);

          this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
          this.ws.send(
            JSON.stringify({
              op: 2,
              d: {
                token: this.token,
                capabilities: 16381,
                properties: localProps(),
                presence: { status: "online", since: 0, activities: [], afk: false },
              },
            })
          );
        } else if (op === 1) {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
          }
        } else if (op === 0) {
          if (t === "READY") {
            const u = d.user || {};
            this.user_id = String(u.id || "");
            this.username = u.username || "alt";
            this.console.ok("viewer", `alt account connected (${this.username})`);

            this.ws.send(
              JSON.stringify({
                op: 4,
                d: {
                  guild_id: this.guild_id,
                  channel_id: this.channel_id,
                  self_mute: true,
                  self_deaf: true,
                  self_video: false,
                },
              })
            );
            this.console.ok("viewer", `alt account joined voice channel #${this.channel_id}`);

            if (this.stream_key) {
              setTimeout(() => this.watch(this.stream_key), 1000);
            }
          } else if (t === "STREAM_CREATE") {
            const key = d.stream_key;
            if (key && (!this.stream_key || key === this.stream_key)) {
              setTimeout(() => this.watch(key), 500);
            }
          }
        }
      } catch {
        // Ignore
      }
    });

    this.ws.on("close", () => {
      if (this.hb_timer) {
        clearInterval(this.hb_timer);
        this.hb_timer = null;
      }
      if (this.running) {
        setTimeout(() => this.run(), 3000);
      }
    });

    this.ws.on("error", () => {
      // Handled by close
    });
  }

  stop() {
    this.running = false;
    if (this.hb_timer) {
      clearInterval(this.hb_timer);
      this.hb_timer = null;
    }
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // Ignore
      }
      this.ws = null;
    }
  }
}

/**
 * GatewayStreamEngine manages the Discord Gateway session, Voice Connections,
 * Go Live Stream creation, ticker, and statistics.
 */
export class GatewayStreamEngine {
  constructor(state, session, consoleObj) {
    this.state = state;
    this.session = session;
    this.console = consoleObj;

    this.ws = null;
    this.hb_timer = null;
    this.ticker_timer = null;
    this.running = false;
    this.start_time = 0;
    this.counted_stream_seconds = 0.0;
    this._saved_stream_seconds = 0.0;
    this.stopped_by_user = false;

    this.user_id = userIdFromToken(this.state.token) || "";
    this.gateway_session_id = null;
    this.voice_session_id = null;
    this.sequence = null;

    this.guild_id = "";
    this.channel_id = "";
    this.channel_name = "";
    this.stream_key = "";

    this.voice_connected = false;
    this.stream_connected = false;
    this.stream_ever_active = false;
    this.detected_guild_id = "";
    this.detected_channel_id = "";
    this._was_already_in_vc = false;
    this._user_left_vc = false;

    this.voice_conn = null;
    this.stream_conn = null;
    this.viewer_engine = null;

    this.channel_members = new Set();
    this.stream_viewer_ids = new Set();
  }

  getViewerCount() {
    const vcCount = this.channel_members.size;
    const streamCount = this.stream_viewer_ids.size;
    return Math.max(vcCount, streamCount);
  }

  startStream(guildId = "", channelId = "", waitForStdin = false) {
    return new Promise(async (resolve) => {
      const C = this.console;
      C.rule();
      C.info(`${C.MAGENTA}Headless Gateway Live Streamer (Node.js)${C.WHITE}`);
      C.rule();
      C.info("connecting to discord gateway (wss://gateway.discord.gg)...");

      this.running = true;
      this.start_time = Date.now();
      this.counted_stream_seconds = 0.0;
      this._saved_stream_seconds = 0.0;
      this.guild_id = guildId;
      this.channel_id = channelId;

      const wsUrl = `wss://${GATEWAY_URL}/?v=9&encoding=json`;
      try {
        this.ws = new WebSocket(wsUrl);
      } catch (exc) {
        C.err("gateway", `connection failed: ${exc.message || exc}`);
        C.rule();
        this.cleanup();
        return resolve();
      }

      this.ws.on("open", () => {
        C.ok("gateway", "connected");
      });

      this.ws.on("message", (raw) => {
        try {
          const msg = JSON.parse(raw.toString("utf8"));
          const { op, s, t, d } = msg;

          if (s !== null && s !== undefined) {
            this.sequence = s;
          }

          if (op === 10) {
            // Hello
            const interval = (d.heartbeat_interval || 41250) / 1000;
            if (this.hb_timer) clearInterval(this.hb_timer);
            this.hb_timer = setInterval(() => {
              if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
              }
            }, interval * 1000);

            this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
            this.ws.send(
              JSON.stringify({
                op: 2,
                d: {
                  token: this.state.token,
                  capabilities: 16381,
                  properties: localProps(),
                  presence: { status: "online", since: 0, activities: [], afk: false },
                },
              })
            );
          } else if (op === 1) {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.send(JSON.stringify({ op: 1, d: this.sequence }));
            }
          } else if (op === 0) {
            this.handleDispatch(t, d || {});
          }
        } catch {
          // Ignore
        }
      });

      this.ws.on("close", () => {
        if (!this.stopped_by_user && this.running) {
          C.warn("gateway", "connection closed by server");
        }
      });

      this.ws.on("error", (err) => {
        C.err("gateway", `socket error: ${err.message || err}`);
      });

      this.ticker_timer = setInterval(() => {
        if (!this.running) return;
        if (this.stream_connected && this.getViewerCount() > 0) {
          this.counted_stream_seconds += 1.0;
          const newSeconds = this.counted_stream_seconds - this._saved_stream_seconds;
          if (newSeconds >= 10) {
            this.state.total_stream_hours_claimed += newSeconds / 3600.0;
            this._saved_stream_seconds = this.counted_stream_seconds;
            this.state.save();
          }
        }
      }, 1000);
    });
  }

  async handleDispatch(eventType, d) {
    const C = this.console;

    if (eventType === "READY") {
      this.gateway_session_id = d.session_id || "";
      const userData = d.user || {};
      const username = userData.username || "?";
      this.user_id = String(userData.id || this.user_id);
      C.ok("auth", `gateway authenticated (${username})`);

      if (!this.channel_id && !this.detected_channel_id) {
        C.info("auto discovering voice room across user servers...");
        const room = await findRandomVoiceChannelFromToken(this.state.token);
        if (room && room.channel_id) {
          this.guild_id = room.guild_id;
          this.channel_id = room.channel_id;
          this.channel_name = room.channel_name;
          C.ok("voice", `auto selected voice room #${room.channel_name} (${room.guild_name})`);
        }
      }

      const targetGid = this.guild_id || this.detected_guild_id;
      const targetCid = this.channel_id || this.detected_channel_id;
      if (targetCid && this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(
          JSON.stringify({
            op: 4,
            d: {
              guild_id: targetGid,
              channel_id: targetCid,
              self_mute: false,
              self_deaf: false,
              self_video: false,
            },
          })
        );
      }
    } else if (eventType === "READY_SUPPLEMENTAL") {
      const guilds = d.guilds || [];
      for (const g of guilds) {
        const gid = String(g.id);
        const vstates = g.voice_states || [];
        for (const vs of vstates) {
          const vsUid = String(vs.user_id);
          const vsCid = String(vs.channel_id || "");
          if (vsUid === String(this.user_id) && vsCid) {
            this.detected_guild_id = gid;
            this.detected_channel_id = vsCid;
            if (vs.session_id) this.voice_session_id = vs.session_id;
          } else if (this.channel_id && vsCid === String(this.channel_id) && vsUid !== String(this.user_id)) {
            this.channel_members.add(vsUid);
          }
        }
      }
    } else if (eventType === "VOICE_STATE_UPDATE") {
      const vsUserId = String(d.user_id);
      const vsChannelId = d.channel_id ? String(d.channel_id) : null;
      const vsGuildId = String(d.guild_id || "");

      if (vsUserId === String(this.user_id)) {
        if (d.session_id) this.voice_session_id = d.session_id;
        if (!vsChannelId && this.stream_connected) {
          C.warn("voice", "voice channel connection dropped, auto-rejoining in 2s...");
          setTimeout(() => {
            if (this.running && this.ws && this.ws.readyState === WebSocket.OPEN && this.channel_id) {
              this.ws.send(
                JSON.stringify({
                  op: 4,
                  d: {
                    guild_id: this.guild_id,
                    channel_id: this.channel_id,
                    self_mute: false,
                    self_deaf: false,
                    self_video: false,
                  },
                })
              );
            }
          }, 2000);
        }
      } else if (this.channel_id) {
        if (vsChannelId && vsChannelId === String(this.channel_id)) {
          const wasZero = this.getViewerCount() === 0;
          this.channel_members.add(vsUserId);
          if (wasZero && this.stream_connected) {
            C.ok("viewer", `viewer joined voice channel (${this.channel_members.size} member(s) present) — stream hour accumulation RESUMED!`);
          }
        } else {
          if (this.channel_members.has(vsUserId)) {
            this.channel_members.delete(vsUserId);
            if (this.getViewerCount() === 0 && this.stream_connected) {
              C.warn("viewer", "⚠️  all viewers left voice channel (0 present) — stream hour accumulation PAUSED!");
            }
          }
        }
      }
    } else if (eventType === "VOICE_SERVER_UPDATE") {
      const token = d.token || "";
      const endpoint = d.endpoint || "";
      const vGuild = d.guild_id || this.guild_id;

      if (!endpoint || !token) return;

      if (this.voice_conn) {
        this.voice_conn.close();
      }

      C.ok("voice", `voice server: ${endpoint}`);
      const sessionId = this.voice_session_id || this.gateway_session_id;
      this.voice_conn = new VoiceConnection({
        endpoint,
        server_id: vGuild,
        user_id: this.user_id,
        session_id: sessionId,
        token,
        console: C,
        label: "voice",
        is_stream: false,
        channel_id: this.channel_id,
      });

      C.info("performing voice WebSocket handshake...");
      const connected = await this.voice_conn.connect();
      if (connected) {
        this.voice_conn.startHeartbeat();
        this.voice_conn.sendSpeaking(false);
        this.voice_conn.startSilencePump();
        this.voice_connected = true;
        C.ok("voice", `${C.GREEN}voice connection established (ssrc=${this.voice_conn.ssrc})${C.RESET}`);

        setTimeout(() => {
          C.info("requesting Go Live stream (op 18 Stream Create)...");
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(
              JSON.stringify({
                op: 18,
                d: {
                  type: "guild",
                  guild_id: this.guild_id,
                  channel_id: this.channel_id,
                  preferred_region: null,
                },
              })
            );
          }
        }, 500);
      }
    } else if (eventType === "STREAM_CREATE") {
      this.stream_key = d.stream_key || "";
      this.rtc_server_id = d.rtc_server_id || "";
      C.ok("stream", `Go Live created! stream_key: ${C.CYAN}${this.stream_key}${C.RESET}`);
      this.stream_connected = true;
      this.stream_ever_active = true;

      if (d.viewer_ids && Array.isArray(d.viewer_ids)) {
        this.stream_viewer_ids = new Set(d.viewer_ids.map(String).filter((u) => u !== String(this.user_id)));
      }

      if (this.ws && this.ws.readyState === WebSocket.OPEN && this.stream_key) {
        this.ws.send(JSON.stringify({ op: 22, d: { stream_key: this.stream_key, paused: false } }));
        C.ok("stream", "stream marked unpaused (Opcode 22 STREAM_SET_PAUSED: paused=false)");
      }

      if (this.state.viewer_token && !this.viewer_engine) {
        this.viewer_engine = new ViewerEngine(this.state.viewer_token, C);
        this.viewer_engine.start(this.guild_id, this.channel_id);
      }
      if (this.viewer_engine && this.stream_key) {
        this.viewer_engine.watch(this.stream_key);
      }

      console.log();
      C.rule();
      C.live("stream", `${C.MAGENTA}● BROADCASTING LIVE${C.RESET}, discord shows your account as ${C.MAGENTA}LIVE${C.RESET}`);
      C.rule();

      const viewers = this.getViewerCount();
      if (viewers === 0) {
        C.warn("viewer", "⚠️  NO VIEWERS DETECTED (0 in VC) - stream hour accumulation is PAUSED!");
        C.warn("viewer", "› Discord requires at least 1 other user in VC or watching stream to count hours.");
      } else {
        const lbl = viewers === 1 ? "1 viewer" : `${viewers} viewers`;
        C.ok("viewer", `✓ ${lbl} detected in voice channel - stream hour accumulation is ACTIVE`);
      }
    } else if (eventType === "STREAM_UPDATE") {
      if (d.viewer_ids && Array.isArray(d.viewer_ids)) {
        this.stream_viewer_ids = new Set(d.viewer_ids.map(String).filter((u) => u !== String(this.user_id)));
      }
    } else if (eventType === "STREAM_SERVER_UPDATE") {
      const token = d.token || "";
      const endpoint = d.endpoint || "";
      const sKey = d.stream_key || this.stream_key;

      if (endpoint && token) {
        C.ok("stream", `stream media route: ${endpoint}`);
        if (this.stream_conn) {
          this.stream_conn.close();
        }

        const targetServer = this.rtc_server_id || d.rtc_server_id || d.guild_id || this.guild_id || this.channel_id;
        const vSession = this.voice_session_id || this.gateway_session_id;

        this.stream_conn = new VoiceConnection({
          endpoint,
          server_id: targetServer,
          user_id: this.user_id,
          session_id: vSession,
          token,
          console: C,
          label: "stream_rtc",
          is_stream: true,
          stream_key: sKey,
          channel_id: this.channel_id,
        });

        const ok = await this.stream_conn.connect();
        if (ok) {
          this.stream_conn.startHeartbeat();
          const vSsrc = this.stream_conn.video_ssrc;
          const rSsrc = this.stream_conn.rtx_ssrc;
          const streamDesc = {
            op: 12,
            d: {
              audio_ssrc: this.stream_conn.ssrc,
              video_ssrc: vSsrc,
              rtx_ssrc: rSsrc,
              streams: [
                {
                  type: "video",
                  rid: "100",
                  ssrc: vSsrc,
                  rtx_ssrc: rSsrc,
                  active: true,
                  quality: 100,
                  max_bitrate: 2500000,
                  max_framerate: 30,
                  max_resolution: { type: "fixed", width: 848, height: 480 },
                },
              ],
            },
          };
          this.stream_conn.ws.send(JSON.stringify(streamDesc));
          this.stream_conn.sendSpeaking(true);
          C.ok("stream_rtc", `stream media connection active (ssrc=${this.stream_conn.ssrc})`);

          const mediaSource = resolveMediaSource(this.state.stream_url, C);
          if (mediaSource) {
            if (!this.stream_conn.startMediaStream(mediaSource)) {
              C.warn("stream_rtc", "falling back to silent audio pump");
              this.stream_conn.startSilencePump();
            }
          } else {
            this.stream_conn.startSilencePump();
          }
        }
      }
    }
  }

  stop() {
    this.stopped_by_user = true;
    this.cleanup();
  }

  cleanup() {
    const C = this.console;
    this.running = false;

    if (this.ticker_timer) {
      clearInterval(this.ticker_timer);
      this.ticker_timer = null;
    }
    if (this.hb_timer) {
      clearInterval(this.hb_timer);
      this.hb_timer = null;
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN && this.stream_key) {
      try {
        this.ws.send(JSON.stringify({ op: 19, d: { stream_key: this.stream_key } }));
      } catch {
        // Ignore
      }
    }

    if (this.viewer_engine) {
      this.viewer_engine.stop();
      this.viewer_engine = null;
    }
    if (this.stream_conn) {
      this.stream_conn.close();
      this.stream_conn = null;
    }
    if (this.voice_conn) {
      this.voice_conn.close();
      this.voice_conn = null;
    }
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // Ignore
      }
      this.ws = null;
    }

    if (this.stream_connected || this.stream_ever_active) {
      const countedHours = this.counted_stream_seconds / 3600.0;
      const elapsedWall = (Date.now() - this.start_time) / 1000;
      const newSeconds = Math.max(0, this.counted_stream_seconds - this._saved_stream_seconds);
      if (newSeconds >= 5) {
        this.state.total_stream_hours_claimed += newSeconds / 3600.0;
        this._saved_stream_seconds = this.counted_stream_seconds;
        if (this.stopped_by_user) {
          this.state.total_stream_sessions += 1;
        }
        this.state.save();
      }

      console.log();
      if (this.counted_stream_seconds >= 10) {
        C.ok(
          "stream",
          `ended · ${formatTimer(this.counted_stream_seconds)} (${countedHours.toFixed(2)}h) counted streaming hours (${formatTimer(elapsedWall)} wall time)`
        );
      } else {
        C.info("stream session ended.");
      }
    }
  }
}

export async function validateStreamTarget(token, channelId) {
  try {
    const res = await fetch(`${USERS_URL.replace("/users", "")}/channels/${channelId}`, {
      headers: { authorization: token, "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const data = await res.json();
      return { valid: true, guild_id: data.guild_id || "", name: data.name || "voice" };
    }
  } catch {
    // Ignore
  }
  return { valid: false, guild_id: "", name: "" };
}

export async function findRandomVoiceChannelFromToken(token) {
  try {
    const guildsRes = await fetch("https://discord.com/api/v9/users/@me/guilds", {
      headers: { authorization: token, "user-agent": USER_AGENT },
      signal: AbortSignal.timeout(10000),
    });
    if (!guildsRes.ok) return null;
    const guilds = await guildsRes.json();
    if (!Array.isArray(guilds) || !guilds.length) return null;

    // Shuffle guilds
    const shuffled = guilds.sort(() => Math.random() - 0.5);
    for (const g of shuffled.slice(0, 10)) {
      const chRes = await fetch(`https://discord.com/api/v9/guilds/${g.id}/channels`, {
        headers: { authorization: token, "user-agent": USER_AGENT },
        signal: AbortSignal.timeout(10000),
      });
      if (chRes.ok) {
        const channels = await chRes.json();
        const voiceChannels = channels.filter((c) => c.type === 2 || c.type === 13);
        if (voiceChannels.length > 0) {
          const picked = voiceChannels[Math.floor(Math.random() * voiceChannels.length)];
          return {
            guild_id: g.id,
            guild_name: g.name,
            channel_id: picked.id,
            channel_name: picked.name,
          };
        }
      }
    }
  } catch {
    // Ignore
  }
  return null;
}

export function extractChannelId(inputStr) {
  const match = String(inputStr || "").match(/\d{17,20}/);
  return match ? match[0] : "";
}

export async function inspectProfile(state, session, consoleObj) {
  const C = consoleObj;
  if (!state.hasToken) {
    C.err("auth", "no token saved");
    return;
  }
  C.info("fetching profile data from discord...");
  let uid = userIdFromToken(state.token);
  if (!uid) {
    try {
      const res = await fetch(ME_URL, {
        headers: { authorization: state.token, "user-agent": USER_AGENT, "x-super-properties": session.super_props },
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) {
        const data = await res.json();
        uid = data.id || "";
      }
    } catch {
      // Ignore
    }
  }

  if (!uid) {
    C.err("profile", "unable to resolve user id from token");
    return;
  }

  const url = `${USERS_URL}/${uid}/profile?with_mutual_guilds=false&with_mutual_friends_count=false`;
  try {
    const res = await fetch(url, {
      headers: { authorization: state.token, "user-agent": USER_AGENT, "x-super-properties": session.super_props },
      signal: AbortSignal.timeout(15000),
    });
    if (res.ok) {
      const data = await res.json();
      const user = data.user || {};
      const badges = data.badges || [];
      C.rule();
      const username = user.username || "Unknown";
      const globalName = user.global_name;
      const display = globalName ? `${globalName} (@${username})` : `@${username}`;
      C.ok("account", `${display} · ID: ${uid}`);

      if (badges.length) {
        C.info(`badges (${badges.length}):`);
        for (const b of badges) {
          const bid = b.id || "badge";
          const desc = b.description || "";
          C.info(`  ${C.CYAN}•${C.WHITE} ${C.ORANGE}${bid}${C.WHITE}: ${desc}`);
        }
      } else {
        C.info("no public badges equipped on profile");
      }
    } else {
      C.err("profile", `HTTP ${res.status}`);
    }
  } catch (exc) {
    C.err("profile", `failed to load: ${exc.message || exc}`);
  }
}

// Interactive CLI Menu
export class StreamMaximizerApp {
  constructor() {
    this.console = new Console();
    this.state = State.load();
    this.session = null;
  }

  async start(autoMenu = true) {
    this.session = await Session.new();
    if (autoMenu) {
      await this.menu();
    }
    return true;
  }

  async menu() {
    const C = this.console;
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const prompt = async (msg) => {
      try {
        return (await rl.question(msg)).trim();
      } catch {
        return "";
      }
    };

    try {
      while (true) {
        C.banner();
        const viewerStatus = this.state.hasViewerToken
          ? `${C.GREEN}enabled${C.RESET}`
          : `${C.GREY}none (optional)${C.RESET}`;
        C.info(
          `total stream hours: ${C.ORANGE}${this.state.total_stream_hours_claimed.toFixed(1)}h${C.WHITE} ` +
            `(${this.state.total_stream_sessions} sessions) · alt viewer: ${viewerStatus}`
        );
        C.rule();
        C.info(`${C.ORANGE}1${C.RESET} · ${C.MAGENTA}Start Live Stream${C.RESET} (Gateway AFK Go Live Broadcast)`);
        C.info(`${C.ORANGE}2${C.RESET} · Inspect Discord Profile & Badges`);
        C.info(`${C.ORANGE}3${C.RESET} · ${C.CYAN}Configure Alt Viewer Token${C.RESET} (${C.GREEN}Auto Opcode 20 STREAM_WATCH${C.RESET})`);
        C.info(`${C.ORANGE}4${C.RESET} · Refresh Auth (Token & Cookie)`);
        C.info(`${C.ORANGE}5${C.RESET} · Reset Main Account Token`);
        C.info(`${C.ORANGE}6${C.RESET} · Reset Alt Account Token`);
        C.info(`${C.ORANGE}7${C.RESET} · Exit`);
        C.rule();

        const choice = await prompt(`  ${C.ORANGE}›${C.RESET} `);
        console.log();

        if (choice === "1") {
          const engine = new GatewayStreamEngine(this.state, this.session, C);
          const channelId = this.state.last_channel_id || "";
          const guildId = this.state.last_guild_id || "";
          engine.startStream(guildId, channelId);
          await prompt(`  ${C.ORANGE}›${C.RESET} Streaming running. Press enter to stop...`);
          engine.stop();
        } else if (choice === "2") {
          await inspectProfile(this.state, this.session, C);
          await prompt(`  ${C.ORANGE}›${C.RESET} Press enter to continue`);
        } else if (choice === "3") {
          const vtok = await prompt(`  ${C.GREY}alt viewer token:${C.RESET} `);
          if (vtok) {
            this.state.viewer_token = vtok;
            this.state.save();
            C.ok("viewer", "Alt account token saved!");
          }
          await new Promise((r) => setTimeout(r, 1000));
        } else if (choice === "4") {
          const tok = await prompt(`  ${C.GREY}main account token:${C.RESET} `);
          if (tok) this.state.token = tok;
          const ck = await prompt(`  ${C.GREY}cookie cf_clearance:${C.RESET} `);
          if (ck) this.state.cookie = ck;
          this.state.save();
          C.ok("auth", "Auth credentials saved!");
          await new Promise((r) => setTimeout(r, 1000));
        } else if (choice === "5") {
          this.state.token = "";
          this.state.save();
          C.warn("auth", "Main token reset");
          await new Promise((r) => setTimeout(r, 1000));
        } else if (choice === "6") {
          this.state.viewer_token = "";
          this.state.save();
          C.warn("viewer", "Alt token reset");
          await new Promise((r) => setTimeout(r, 1000));
        } else if (["7", "q", "exit", ""].includes(choice)) {
          break;
        }
      }
    } finally {
      rl.close();
    }
  }
}

// Entrypoint
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  let autoStream = false;
  let targetChannel = "";
  let targetGuild = "";
  let doProfile = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--stream" || args[i] === "--auto") {
      autoStream = true;
    } else if (args[i] === "--channel" && i + 1 < args.length) {
      targetChannel = args[++i];
    } else if (args[i] === "--guild" && i + 1 < args.length) {
      targetGuild = args[++i];
    } else if (args[i] === "--profile") {
      doProfile = true;
    }
  }

  const app = new StreamMaximizerApp();
  app.start(!autoStream && !doProfile).then(async () => {
    if (doProfile) {
      await inspectProfile(app.state, app.session, app.console);
      process.exit(0);
    } else if (autoStream) {
      const cid = targetChannel || app.state.last_channel_id;
      const gid = targetGuild || app.state.last_guild_id;
      const engine = new GatewayStreamEngine(app.state, app.session, app.console);
      await engine.startStream(gid, cid);
    }
  });
}
