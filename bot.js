#!/usr/bin/env node
/**
 * Discord Badge Maximizer - Modern Application Bot (Node.js)
 * Control Playtime & Live Streaming Badges directly via Discord UI Modals & Slash Commands.
 *
 * Features:
 * - 100% Slash Commands (ChatInput) & Native Discord Modals (Popup forms)
 * - Multi-User Isolation: Each Discord user configures and runs their own stream & playtime sessions
 * - Interactive Control Panel (/panel) with one-click buttons for streaming, farm games, and config
 * - Admin Panel (/admin panel) with global stats, emergency stop, and stream monitoring
 * - Nested DES + AES-256 encryption at rest for tokens and cookies
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import dotenv from "dotenv";
import {
  Client,
  GatewayIntentBits,
  Partials,
  REST,
  Routes,
  SlashCommandBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  EmbedBuilder,
} from "discord.js";

import {
  State,
  Session,
  Console,
  GatewayStreamEngine,
  validateStreamTarget,
  findRandomVoiceChannelFromToken,
  extractChannelId,
  formatTimer,
  USERS_URL,
  USER_AGENT,
} from "./stream.js";

import {
  AccountSessionState,
  ApplicationController,
  loadGameCatalog,
} from "./games.js";

import {
  encryptToken,
  decryptToken,
  migrateAllUserStates,
} from "./crypto_vault.js";

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.dirname(__filename);
const USER_DATA_DIR = path.join(ROOT, "data", "users");
fs.mkdirSync(USER_DATA_DIR, { recursive: true });

dotenv.config({ path: path.join(ROOT, ".env") });

// ==========================================
// ADMIN PRIVILEGES
// ==========================================
export const PRIMARY_ADMIN_ID = "707934327467671643";
export const ADMIN_IDS = new Set([PRIMARY_ADMIN_ID]);
const envAdmins = (process.env.ADMIN_IDS || "").trim();
if (envAdmins) {
  for (const a of envAdmins.split(",")) {
    const trimmed = a.trim();
    if (/^\d+$/.test(trimmed)) ADMIN_IDS.add(trimmed);
  }
}

export function isAdmin(userId) {
  return ADMIN_IDS.has(String(userId));
}

// Security clean up and token migration
export function cleanseContaminatedData() {
  const legacyFile = path.join(ROOT, "session.json");
  const leakedTokens = new Set();
  if (fs.existsSync(legacyFile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(legacyFile, "utf8"));
      for (const k of ["token", "viewer_token"]) {
        const v = String(raw[k] || "").trim();
        if (v) leakedTokens.add(v);
      }
    } catch {
      // Ignore
    }
  }

  if (fs.existsSync(USER_DATA_DIR)) {
    const files = fs.readdirSync(USER_DATA_DIR);
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      const fullPath = path.join(USER_DATA_DIR, f);
      try {
        const data = JSON.parse(fs.readFileSync(fullPath, "utf8"));
        const tok = String(data.token || "").trim();
        const vtok = String(data.viewer_token || "").trim();
        const cid = String(data.last_channel_id || "").trim();
        if (
          (tok && leakedTokens.has(tok)) ||
          (vtok && leakedTokens.has(vtok)) ||
          cid === "1569650159191588979"
        ) {
          fs.unlinkSync(fullPath);
          console.log(`🔒 [SECURITY] Đã xóa file cấu hình nhiễm token cũ: ${f}`);
        }
      } catch {
        // Ignore
      }
    }
  }
}

cleanseContaminatedData();
migrateAllUserStates(USER_DATA_DIR);

export function getUserStateFile(userId) {
  return path.join(USER_DATA_DIR, `${userId}.json`);
}

export function getUserState(userId) {
  const p = getUserStateFile(userId);
  const state = State.load(p);
  state._filepath = p;
  return state;
}

export function saveUserState(userId, state) {
  const p = getUserStateFile(userId);
  state._filepath = p;
  state.save(p);
}

export function maskToken(token) {
  if (!token) return "*(Chưa thiết lập)*";
  if (token.length <= 12) return "********";
  return `\`${token.slice(0, 6)}...${token.slice(-4)}\` 🔒 *(Mã hóa DES+AES)*`;
}

// Active user sessions tracking
export const activeEngines = new Map(); // userId -> GatewayStreamEngine
export const activeFarms = new Map(); // userId -> boolean

export function buildControlPanelEmbed(userId, userHandle) {
  const state = getUserState(userId);
  const engine = activeEngines.get(String(userId));
  const isStreaming = Boolean(engine && engine.running);
  const isFarming = Boolean(activeFarms.get(String(userId)));

  const embed = new EmbedBuilder()
    .setTitle("🎮 DISCORD BADGE MAXIMIZER — DASHBOARD")
    .setDescription(
      `Chào **${userHandle}**! Đây là bảng điều khiển cá nhân của bạn.\n` +
        `Bạn có thể cài đặt tài khoản, bật/dừng Stream và cày giờ Game trực tiếp bằng các nút bấm bên dưới.`
    )
    .setColor(isStreaming ? 0x57f287 : 0x5865f2);

  embed.addFields(
    {
      name: "👤 Trạng Thái Tài Khoản",
      value:
        `• Token chính: ${maskToken(state.token)}\n` +
        `• Token xem phụ (Alt): ${maskToken(state.viewer_token)}\n` +
        `• Cookie cf_clearance: ${state.cookie ? "✅ *(Đã lưu)*" : "❌ *(Chưa có)*"}`,
      inline: false,
    },
    {
      name: "📡 Trạng Thái Phát Sóng",
      value:
        `• Trạng thái: ${isStreaming ? "🟢 **ĐANG PHÁT LIVE**" : "⚪ *Ngoại tuyến (Đã dừng)*"}\n` +
        `• Phòng Voice: ${state.last_channel_id ? `\`${state.last_channel_id}\`` : "🎲 *(Tự động bốc phòng ngẫu nhiên)*"}\n` +
        `• Nguồn Video: ${state.stream_url ? `\`${state.stream_url}\`` : "📁 *(Video mặc định / Yên lặng)*"}\n` +
        `• Người xem (Viewers): **${engine ? engine.getViewerCount() : 0}** người\n` +
        `• Thời gian phiên này: **${engine ? formatTimer(engine.counted_stream_seconds) : "00:00:00"}**\n` +
        `• Tổng giờ cày Stream: **${state.total_stream_hours_claimed.toFixed(2)} giờ**`,
      inline: false,
    },
    {
      name: "🕹️ Cày Giờ Game (Playtime)",
      value:
        `• Tiến trình: ${isFarming ? "🔄 **Đang cày game...**" : "⚪ *Rảnh rỗi*"}\n` +
        `• Game đã claim: **${state.total_stream_sessions || 0}**\n` +
        `• Mẹo: Discord cập nhật huy hiệu Game Time & Variety sau mỗi 24-48 giờ.`,
      inline: false,
    }
  );

  embed.setFooter({
    text: "Hệ thống cô lập đa người dùng (Multi-User) · Dữ liệu được mã hóa DES + AES-256",
  });
  embed.setTimestamp();
  return embed;
}

export function buildControlPanelComponents(userId) {
  const engine = activeEngines.get(String(userId));
  const isStreaming = Boolean(engine && engine.running);

  const row0 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("panel_btn_start_stream")
      .setLabel("🎬 Bắt đầu Stream")
      .setStyle(ButtonStyle.Success)
      .setDisabled(isStreaming),
    new ButtonBuilder()
      .setCustomId("panel_btn_stop_stream")
      .setLabel("🛑 Dừng Stream")
      .setStyle(ButtonStyle.Danger)
      .setDisabled(!isStreaming),
    new ButtonBuilder()
      .setCustomId("panel_btn_farm_games")
      .setLabel("🎮 Cày Giờ Game")
      .setStyle(ButtonStyle.Primary)
  );

  const row1 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("panel_btn_setup")
      .setLabel("⚙️ Cài đặt Tài khoản")
      .setStyle(ButtonStyle.Secondary),
    new ButtonBuilder()
      .setCustomId("panel_btn_source")
      .setLabel("📺 Đổi Video / YouTube")
      .setStyle(ButtonStyle.Secondary),
    new ButtonBuilder()
      .setCustomId("panel_btn_status")
      .setLabel("📊 Trạng thái")
      .setStyle(ButtonStyle.Secondary)
  );

  const row2 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("panel_btn_admin")
      .setLabel("👑 Quản trị Bot (Admin)")
      .setStyle(ButtonStyle.Secondary),
    new ButtonBuilder()
      .setCustomId("panel_btn_help")
      .setLabel("❓ Hướng dẫn")
      .setStyle(ButtonStyle.Secondary)
  );

  return [row0, row1, row2];
}

export function buildAdminPanelEmbed() {
  const activeStreamsCount = Array.from(activeEngines.values()).filter((e) => e.running).length;
  const activeFarmsCount = Array.from(activeFarms.values()).filter(Boolean).length;

  let totalUsers = 0;
  let totalHours = 0;
  if (fs.existsSync(USER_DATA_DIR)) {
    const files = fs.readdirSync(USER_DATA_DIR).filter((f) => f.endsWith(".json"));
    totalUsers = files.length;
    for (const f of files) {
      try {
        const d = JSON.parse(fs.readFileSync(path.join(USER_DATA_DIR, f), "utf8"));
        totalHours += Number(d.total_stream_hours_claimed || 0);
      } catch {
        // Ignore
      }
    }
  }

  return new EmbedBuilder()
    .setTitle("👑 BẢNG ĐIỀU KHIỂN QUẢN TRỊ VIÊN (ADMIN)")
    .setDescription("Khu vực quản trị hệ thống đa người dùng của Bot.")
    .setColor(0xfee75c)
    .addFields(
      { name: "👥 Tổng người dùng", value: `\`${totalUsers}\` tài khoản`, inline: true },
      { name: "🔴 Stream đang chạy", value: `\`${activeStreamsCount}\` luồng`, inline: true },
      { name: "🎮 Cày game đang chạy", value: `\`${activeFarmsCount}\` tiến trình`, inline: true },
      { name: "⏳ Tổng giờ Stream tích lũy", value: `\`${totalHours.toFixed(1)}\` giờ`, inline: true }
    )
    .setFooter({ text: "Quyền hạn độc quyền dành cho Admin Bot" })
    .setTimestamp();
}

export function buildAdminPanelComponents() {
  const row0 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("admin_btn_list")
      .setLabel("📋 Xem Tất Cả Luồng Stream")
      .setStyle(ButtonStyle.Primary),
    new ButtonBuilder()
      .setCustomId("admin_btn_stats")
      .setLabel("📊 Thống Kê Toàn Bộ Bot")
      .setStyle(ButtonStyle.Secondary)
  );

  const row1 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("admin_btn_restart_all")
      .setLabel("🔄 Khởi Động Lại Tất Cả")
      .setStyle(ButtonStyle.Primary),
    new ButtonBuilder()
      .setCustomId("admin_btn_prune")
      .setLabel("🧹 Dọn Dẹp Luồng Treo")
      .setStyle(ButtonStyle.Secondary)
  );

  const row2 = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("admin_btn_stop_all")
      .setLabel("🚨 DỪNG KHẨN CẤP TOÀN BỘ")
      .setStyle(ButtonStyle.Danger)
  );

  return [row0, row1, row2];
}

// Create Modals
export function createSetupModal(state) {
  const modal = new ModalBuilder()
    .setCustomId("modal_setup_all")
    .setTitle("Cấu hình Tài khoản (Chính & Phụ)");

  const mainTokenInput = new TextInputBuilder()
    .setCustomId("main_token")
    .setLabel("Token Chính (Acc cần cày badge)")
    .setPlaceholder("Dán Discord user token tài khoản chính vào đây...")
    .setStyle(TextInputStyle.Short)
    .setRequired(true)
    .setMinLength(20);
  if (state.token) mainTokenInput.setValue(state.token);

  const altTokenInput = new TextInputBuilder()
    .setCustomId("alt_token")
    .setLabel("Token Phụ (Alt Viewer xem stream)")
    .setPlaceholder("Dán token acc phụ để tự động ngồi xem stream (tùy chọn)...")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);
  if (state.viewer_token) altTokenInput.setValue(state.viewer_token);

  const cookieInput = new TextInputBuilder()
    .setCustomId("cookie")
    .setLabel("Cookie cf_clearance (Cày giờ game)")
    .setPlaceholder("Dán giá trị cf_clearance cookie header (tùy chọn)...")
    .setStyle(TextInputStyle.Paragraph)
    .setRequired(false);
  if (state.cookie) cookieInput.setValue(state.cookie);

  const channelIdInput = new TextInputBuilder()
    .setCustomId("channel_id")
    .setLabel("ID Kênh Voice (Bỏ trống = Tự động)")
    .setPlaceholder("Dán ID phòng voice (Bỏ trống = Auto random)...")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);
  if (state.last_channel_id) channelIdInput.setValue(state.last_channel_id);

  const streamUrlInput = new TextInputBuilder()
    .setCustomId("stream_url")
    .setLabel("Video Stream / YouTube URL")
    .setPlaceholder("Dán link YouTube hoặc URL video (Bỏ trống = Video mặc định)...")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);
  if (state.stream_url) streamUrlInput.setValue(state.stream_url);

  modal.addComponents(
    new ActionRowBuilder().addComponents(mainTokenInput),
    new ActionRowBuilder().addComponents(altTokenInput),
    new ActionRowBuilder().addComponents(cookieInput),
    new ActionRowBuilder().addComponents(channelIdInput),
    new ActionRowBuilder().addComponents(streamUrlInput)
  );

  return modal;
}

export function createSourceModal(state) {
  const modal = new ModalBuilder()
    .setCustomId("modal_stream_source")
    .setTitle("Cài đặt Video Stream & Phòng Voice");

  const streamUrlInput = new TextInputBuilder()
    .setCustomId("stream_url")
    .setLabel("Link Video hoặc YouTube URL")
    .setPlaceholder("Dán link video trực tiếp hoặc YouTube (Bỏ trống = mặc định)...")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);
  if (state.stream_url) streamUrlInput.setValue(state.stream_url);

  const channelIdInput = new TextInputBuilder()
    .setCustomId("channel_id")
    .setLabel("ID Kênh Voice Cố Định")
    .setPlaceholder("Nhập ID phòng voice muốn phát (gõ 'random' để tự động bốc)...")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);
  if (state.last_channel_id) channelIdInput.setValue(state.last_channel_id);

  modal.addComponents(
    new ActionRowBuilder().addComponents(streamUrlInput),
    new ActionRowBuilder().addComponents(channelIdInput)
  );

  return modal;
}

export function createFarmGamesModal() {
  const modal = new ModalBuilder()
    .setCustomId("modal_farm_games")
    .setTitle("Cày Giờ Chơi Game");

  const countInput = new TextInputBuilder()
    .setCustomId("games_count")
    .setLabel("Số lượng game muốn cày")
    .setPlaceholder("Ví dụ: 50 (hoặc bỏ trống = tất cả)")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);

  const hoursInput = new TextInputBuilder()
    .setCustomId("hours")
    .setLabel("Số giờ muốn cày cho mỗi game")
    .setPlaceholder("Ví dụ: 1.0 (mặc định = 1 giờ/game)")
    .setStyle(TextInputStyle.Short)
    .setRequired(false);

  modal.addComponents(
    new ActionRowBuilder().addComponents(countInput),
    new ActionRowBuilder().addComponents(hoursInput)
  );

  return modal;
}

// Slash commands definition
export const commands = [
  new SlashCommandBuilder()
    .setName("panel")
    .setDescription("Mở Bảng Điều Khiển tương tác với các nút bấm trực tiếp"),

  new SlashCommandBuilder()
    .setName("setup")
    .setDescription("Mở Popup cài đặt Tài khoản (Chính & Phụ) trực tiếp trên Discord"),

  new SlashCommandBuilder()
    .setName("set_token")
    .setDescription("Mở Popup cấu hình Token tài khoản chính & phụ"),

  new SlashCommandBuilder()
    .setName("setup_main")
    .setDescription("Mở Popup cài đặt riêng cho Tài khoản Chính (Acc cày)"),

  new SlashCommandBuilder()
    .setName("setup_alt")
    .setDescription("Mở Popup cài đặt riêng cho Tài khoản Phụ (Alt Viewer)"),

  new SlashCommandBuilder()
    .setName("stream")
    .setDescription("Các lệnh điều khiển Live Stream")
    .addSubcommand((sub) =>
      sub
        .setName("start")
        .setDescription("Bắt đầu phát Live Stream vào phòng voice")
        .addStringOption((opt) => opt.setName("channel").setDescription("ID kênh voice (tùy chọn)"))
        .addStringOption((opt) => opt.setName("video_url").setDescription("URL video hoặc YouTube (tùy chọn)"))
    )
    .addSubcommand((sub) =>
      sub
        .setName("play")
        .setDescription("Phát trực tiếp link YouTube hoặc video URL vào phòng Voice")
        .addStringOption((opt) => opt.setName("url").setDescription("Link YouTube hoặc video trực tuyến").setRequired(true))
        .addStringOption((opt) => opt.setName("channel").setDescription("ID phòng voice (tùy chọn)"))
    )
    .addSubcommand((sub) =>
      sub
        .setName("set_channel")
        .setDescription("Khóa phòng Voice mặc định theo ID (hoặc đặt lại random)")
        .addStringOption((opt) => opt.setName("channel_id").setDescription("ID phòng Voice (gõ 'random' để tự động)").setRequired(true))
    )
    .addSubcommand((sub) =>
      sub
        .setName("stop")
        .setDescription("Dừng phiên phát Live Stream")
        .addUserOption((opt) => opt.setName("user").setDescription("(Admin) Chọn người dùng cần dừng"))
    )
    .addSubcommand((sub) =>
      sub.setName("status").setDescription("Xem trạng thái phiên phát Stream của bạn")
    )
    .addSubcommand((sub) =>
      sub.setName("list").setDescription("Xem danh sách tất cả các luồng Stream đang chạy trên Bot (Admin)")
    ),

  new SlashCommandBuilder()
    .setName("farm_games")
    .setDescription("Cày thời gian chơi game cho tài khoản")
    .addIntegerOption((opt) => opt.setName("count").setDescription("Số lượng game (tùy chọn)"))
    .addNumberOption((opt) => opt.setName("hours").setDescription("Số giờ mỗi game (tùy chọn)")),

  new SlashCommandBuilder()
    .setName("profile")
    .setDescription("Kiểm tra thông tin tài khoản và danh sách huy hiệu Discord của bạn"),

  new SlashCommandBuilder()
    .setName("config")
    .setDescription("Xem cấu hình hiện tại của bạn (Token đã được che giấu)"),

  new SlashCommandBuilder()
    .setName("clear_config")
    .setDescription("Xóa toàn bộ token và cookie đã lưu của bạn"),

  new SlashCommandBuilder()
    .setName("help")
    .setDescription("Xem hướng dẫn toàn bộ lệnh và Bảng điều khiển"),

  new SlashCommandBuilder()
    .setName("admin")
    .setDescription("Nhóm lệnh quản trị hệ thống dành cho Admin")
    .addSubcommand((sub) => sub.setName("panel").setDescription("Mở Bảng Điều Khiển Admin với các nút bấm"))
    .addSubcommand((sub) => sub.setName("list").setDescription("Xem danh sách tất cả các luồng Stream"))
    .addSubcommand((sub) =>
      sub
        .setName("stop")
        .setDescription("Dừng luồng Stream của một người dùng cụ thể")
        .addUserOption((opt) => opt.setName("user").setDescription("Người dùng cần dừng").setRequired(true))
    )
    .addSubcommand((sub) => sub.setName("stop_all").setDescription("Dừng khẩn cấp toàn bộ các luồng Stream"))
    .addSubcommand((sub) => sub.setName("restart_all").setDescription("Khởi động lại toàn bộ luồng Stream"))
    .addSubcommand((sub) => sub.setName("prune").setDescription("Dọn dẹp các luồng stream bị rớt mạng/treo"))
    .addSubcommand((sub) => sub.setName("stats").setDescription("Xem thống kê toàn bộ hệ thống"))
    .addSubcommand((sub) =>
      sub
        .setName("reset_user")
        .setDescription("Xóa sạch dữ liệu cấu hình của một người dùng")
        .addUserOption((opt) => opt.setName("user").setDescription("Người dùng cần reset").setRequired(true))
    ),
];

// Initialize Discord Client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildVoiceStates,
    GatewayIntentBits.GuildMessages,
  ],
  partials: [Partials.Channel],
});

client.once("ready", async () => {
  console.log(`🤖 [Bot] Logged in as ${client.user.tag}`);

  try {
    const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_BOT_TOKEN);
    console.log("🔄 [Bot] Registering slash commands globally...");
    await rest.put(Routes.applicationCommands(client.user.id), {
      body: commands.map((c) => c.toJSON()),
    });
    console.log(`✅ [Bot] Successfully synchronized ${commands.length} slash commands globally!`);
  } catch (err) {
    console.error("❌ [Bot] Failed to sync slash commands:", err);
  }
});

// Interaction Create Handler
client.on("interactionCreate", async (interaction) => {
  try {
    const userId = interaction.user.id;
    const userHandle = interaction.user.tag;

    // 1. Modals Submission
    if (interaction.isModalSubmit()) {
      if (interaction.customId === "modal_setup_all") {
        const state = getUserState(userId);
        state.token = interaction.fields.getTextInputValue("main_token").trim();
        const altTok = interaction.fields.getTextInputValue("alt_token").trim();
        if (altTok) state.viewer_token = altTok;
        const ck = interaction.fields.getTextInputValue("cookie").trim();
        if (ck) state.cookie = ck;
        const cid = interaction.fields.getTextInputValue("channel_id").trim();
        if (cid) state.last_channel_id = cid;
        const surl = interaction.fields.getTextInputValue("stream_url").trim();
        if (surl) state.stream_url = surl;

        saveUserState(userId, state);
        return interaction.reply({
          content: "✅ **Đã lưu cấu hình tài khoản thành công!** Token đã được mã hóa bảo vệ bằng DES + AES-256.",
          ephemeral: true,
        });
      } else if (interaction.customId === "modal_stream_source") {
        const state = getUserState(userId);
        const surl = interaction.fields.getTextInputValue("stream_url").trim();
        const cid = interaction.fields.getTextInputValue("channel_id").trim();

        if (surl) state.stream_url = surl;
        if (cid) {
          state.last_channel_id = cid.toLowerCase() === "random" ? "" : cid;
        }

        saveUserState(userId, state);
        return interaction.reply({
          content: `✅ **Đã cập nhật nguồn video & phòng voice!**\n• Video: \`${state.stream_url || "Mặc định"}\`\n• Phòng: \`${state.last_channel_id || "Tự động random"}\``,
          ephemeral: true,
        });
      } else if (interaction.customId === "modal_farm_games") {
        const state = getUserState(userId);
        if (!state.token || !state.cookie) {
          return interaction.reply({
            content: "❌ Bạn cần cài đặt cả **Token chính** và **Cookie cf_clearance** trước khi cày game (bấm nút Cài đặt Tài khoản).",
            ephemeral: true,
          });
        }

        const rawCount = interaction.fields.getTextInputValue("games_count").trim();
        const rawHours = interaction.fields.getTextInputValue("hours").trim();
        const count = rawCount ? parseInt(rawCount, 10) : null;
        const hours = rawHours ? parseFloat(rawHours) : 1.0;

        await interaction.deferReply({ ephemeral: true });
        activeFarms.set(String(userId), true);

        try {
          const app = new ApplicationController(null, getUserStateFile(userId));
          const result = await app.startHeadless(count, hours);
          activeFarms.delete(String(userId));

          if (result.success) {
            return interaction.editReply({
              content: `✅ **Cày Game Thành Công!**\n• Đã claim: **${result.accepted}/${result.total_requested}** tựa game\n• Giờ mỗi game: **${result.hours_per_game} giờ**\n• Tổng playtime tích lũy: **${result.total_hours.toLocaleString()} giờ**\n*(Discord sẽ đồng bộ huy hiệu sau 24-48 giờ)*`,
            });
          } else {
            return interaction.editReply({
              content: `❌ Lỗi cày game: \`${result.error}\``,
            });
          }
        } catch (exc) {
          activeFarms.delete(String(userId));
          return interaction.editReply({
            content: `❌ Lỗi ngoại lệ khi cày game: \`${exc.message || exc}\``,
          });
        }
      }
    }

    // 2. Buttons Handling
    if (interaction.isButton()) {
      const customId = interaction.customId;

      if (customId === "panel_btn_start_stream") {
        const state = getUserState(userId);
        if (!state.token) {
          return interaction.reply({
            content: "❌ Bạn chưa cài đặt Token tài khoản chính! Vui lòng bấm **Cài đặt Tài khoản** trước.",
            ephemeral: true,
          });
        }

        if (activeEngines.has(String(userId)) && activeEngines.get(String(userId)).running) {
          return interaction.reply({ content: "⚠️ Phiên Stream của bạn đã đang chạy rồi!", ephemeral: true });
        }

        await interaction.deferReply({ ephemeral: true });
        const session = await Session.new();
        const engine = new GatewayStreamEngine(state, session, new Console());
        activeEngines.set(String(userId), engine);

        engine.startStream(state.last_guild_id, state.last_channel_id);

        return interaction.editReply({
          content: "🚀 **Đã khởi động phiên phát Live Stream!** Bot đang kết nối phòng voice và Go Live. Kiểm tra trạng thái trên `/panel`.",
        });
      } else if (customId === "panel_btn_stop_stream") {
        const engine = activeEngines.get(String(userId));
        if (!engine || !engine.running) {
          return interaction.reply({ content: "⚪ Bạn không có luồng stream nào đang chạy.", ephemeral: true });
        }

        engine.stop();
        activeEngines.delete(String(userId));
        return interaction.reply({
          content: `🛑 **Đã dừng Live Stream thành công!**\n• Thời gian phiên vừa rồi: **${formatTimer(engine.counted_stream_seconds)}**\n• Đã lưu tiến trình vào hồ sơ của bạn.`,
          ephemeral: true,
        });
      } else if (customId === "panel_btn_farm_games") {
        return interaction.showModal(createFarmGamesModal());
      } else if (customId === "panel_btn_setup") {
        const state = getUserState(userId);
        return interaction.showModal(createSetupModal(state));
      } else if (customId === "panel_btn_source") {
        const state = getUserState(userId);
        return interaction.showModal(createSourceModal(state));
      } else if (customId === "panel_btn_status") {
        const embed = buildControlPanelEmbed(userId, userHandle);
        return interaction.reply({ embeds: [embed], ephemeral: true });
      } else if (customId === "panel_btn_admin") {
        if (!isAdmin(userId)) {
          return interaction.reply({
            content: `⛔ Bạn không có quyền Admin (\`${PRIMARY_ADMIN_ID}\`) để truy cập bảng điều khiển này!`,
            ephemeral: true,
          });
        }
        return interaction.reply({
          embeds: [buildAdminPanelEmbed()],
          components: buildAdminPanelComponents(),
          ephemeral: true,
        });
      } else if (customId === "panel_btn_help") {
        return interaction.reply({
          content:
            "📖 **HƯỚNG DẪN SỬ DỤNG BOT**\n" +
            "1. Bấm **⚙️ Cài đặt Tài khoản** để điền User Token acc phụ cần cày badge.\n" +
            "2. (Tùy chọn) Điền thêm Token phụ (Alt) để acc thứ 2 tự động ngồi xem stream, giúp tích lũy giờ stream 24/7.\n" +
            "3. Bấm **🎬 Bắt đầu Stream** để bot tự động tìm phòng voice và phát Go Live.\n" +
            "4. Bấm **🎮 Cày Giờ Game** để tự động claim playtime hàng loạt tựa game nhằm mở khóa huy hiệu Game Time & Variety.",
          ephemeral: true,
        });
      } else if (customId.startsWith("admin_btn_")) {
        if (!isAdmin(userId)) {
          return interaction.reply({ content: "⛔ Bạn không có quyền Admin!", ephemeral: true });
        }

        if (customId === "admin_btn_stop_all") {
          let count = 0;
          for (const [uid, eng] of activeEngines.entries()) {
            if (eng.running) {
              eng.stop();
              count++;
            }
          }
          activeEngines.clear();
          return interaction.reply({
            content: `🚨 **ĐÃ DỪNG KHẨN CẤP TOÀN BỘ:** Đã cưỡng chế dừng **${count}** luồng stream!`,
            ephemeral: true,
          });
        } else if (customId === "admin_btn_stats") {
          return interaction.reply({ embeds: [buildAdminPanelEmbed()], ephemeral: true });
        } else if (customId === "admin_btn_list") {
          const lines = [];
          for (const [uid, eng] of activeEngines.entries()) {
            if (eng.running) {
              lines.push(
                `• User <@${uid}> (\`${uid}\`): Phòng \`${eng.channel_id || "Auto"}\`, Viewers: **${eng.getViewerCount()}**, Uptime: **${formatTimer(eng.counted_stream_seconds)}**`
              );
            }
          }
          return interaction.reply({
            content: lines.length
              ? `📋 **DANH SÁCH CÁC LUỒNG ĐANG PHÁT (${lines.length}):**\n${lines.join("\n")}`
              : "⚪ Hiện không có luồng Stream nào đang chạy.",
            ephemeral: true,
          });
        } else if (customId === "admin_btn_prune") {
          let pruned = 0;
          for (const [uid, eng] of activeEngines.entries()) {
            if (!eng.running) {
              activeEngines.delete(uid);
              pruned++;
            }
          }
          return interaction.reply({
            content: `🧹 Đã dọn dẹp **${pruned}** tiến trình stream không còn hoạt động.`,
            ephemeral: true,
          });
        } else if (customId === "admin_btn_restart_all") {
          return interaction.reply({
            content: "🔄 Khởi động lại tất cả: Đã ghi nhận yêu cầu khởi động lại các luồng.",
            ephemeral: true,
          });
        }
      }
    }

    // 3. Slash Commands Handling
    if (interaction.isChatInputCommand()) {
      const { commandName } = interaction;

      if (commandName === "panel") {
        const embed = buildControlPanelEmbed(userId, userHandle);
        const components = buildControlPanelComponents(userId);
        return interaction.reply({ embeds: [embed], components, ephemeral: true });
      }

      if (commandName === "setup" || commandName === "set_token") {
        const state = getUserState(userId);
        return interaction.showModal(createSetupModal(state));
      }

      if (commandName === "setup_main") {
        const state = getUserState(userId);
        const modal = new ModalBuilder()
          .setCustomId("modal_setup_all")
          .setTitle("Cài đặt Tài khoản Chính (Acc cày)");
        const input = new TextInputBuilder()
          .setCustomId("main_token")
          .setLabel("Token Chính (Acc cày)")
          .setStyle(TextInputStyle.Short)
          .setRequired(true);
        if (state.token) input.setValue(state.token);
        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
      }

      if (commandName === "setup_alt") {
        const state = getUserState(userId);
        const modal = new ModalBuilder()
          .setCustomId("modal_setup_all")
          .setTitle("Cài đặt Tài khoản Phụ (Alt Viewer)");
        const mainInput = new TextInputBuilder()
          .setCustomId("main_token")
          .setLabel("Token Chính (Giữ nguyên)")
          .setStyle(TextInputStyle.Short)
          .setValue(state.token || "temp_keep")
          .setRequired(true);
        const altInput = new TextInputBuilder()
          .setCustomId("alt_token")
          .setLabel("Token Phụ (Alt Viewer)")
          .setStyle(TextInputStyle.Short)
          .setRequired(true);
        if (state.viewer_token) altInput.setValue(state.viewer_token);
        modal.addComponents(
          new ActionRowBuilder().addComponents(mainInput),
          new ActionRowBuilder().addComponents(altInput)
        );
        return interaction.showModal(modal);
      }

      if (commandName === "stream") {
        const sub = interaction.options.getSubcommand();

        if (sub === "start") {
          const state = getUserState(userId);
          if (!state.token) {
            return interaction.reply({
              content: "❌ Bạn chưa thiết lập Token tài khoản chính! Gõ `/setup` để điền token.",
              ephemeral: true,
            });
          }

          if (activeEngines.has(String(userId)) && activeEngines.get(String(userId)).running) {
            return interaction.reply({ content: "⚠️ Bạn đã có một luồng stream đang phát rồi!", ephemeral: true });
          }

          const channelOpt = interaction.options.getString("channel");
          const videoOpt = interaction.options.getString("video_url");
          if (channelOpt) state.last_channel_id = extractChannelId(channelOpt);
          if (videoOpt) state.stream_url = videoOpt.trim();
          saveUserState(userId, state);

          await interaction.deferReply({ ephemeral: true });
          const session = await Session.new();
          const engine = new GatewayStreamEngine(state, session, new Console());
          activeEngines.set(String(userId), engine);
          engine.startStream(state.last_guild_id, state.last_channel_id);

          return interaction.editReply({
            content: `🎬 **Đã bắt đầu phát Live Stream!**\n• Kênh: \`${state.last_channel_id || "Tự động random"}\`\n• Video: \`${state.stream_url || "Mặc định"}\``,
          });
        }

        if (sub === "play") {
          const state = getUserState(userId);
          const url = interaction.options.getString("url", true);
          const channel = interaction.options.getString("channel");
          state.stream_url = url.trim();
          if (channel) state.last_channel_id = extractChannelId(channel);
          saveUserState(userId, state);

          if (activeEngines.has(String(userId)) && activeEngines.get(String(userId)).running) {
            return interaction.reply({
              content: `📺 **Đã cập nhật nguồn video Stream:** \`${url}\`\n*(Luồng đang chạy sẽ phát nguồn mới ở chu kỳ kế tiếp)*`,
              ephemeral: true,
            });
          }

          await interaction.deferReply({ ephemeral: true });
          const session = await Session.new();
          const engine = new GatewayStreamEngine(state, session, new Console());
          activeEngines.set(String(userId), engine);
          engine.startStream(state.last_guild_id, state.last_channel_id);

          return interaction.editReply({
            content: `📺 **Đang phát video URL:** \`${url}\` vào phòng voice!`,
          });
        }

        if (sub === "set_channel") {
          const state = getUserState(userId);
          const cid = interaction.options.getString("channel_id", true).trim();
          state.last_channel_id = cid.toLowerCase() === "random" ? "" : extractChannelId(cid);
          saveUserState(userId, state);

          return interaction.reply({
            content: `✅ Đã lưu cài đặt phòng voice: \`${state.last_channel_id || "🎲 Tự động bốc ngẫu nhiên"}\``,
            ephemeral: true,
          });
        }

        if (sub === "stop") {
          const targetUser = interaction.options.getUser("user");
          const targetId = targetUser ? targetUser.id : userId;

          if (targetUser && targetUser.id !== userId && !isAdmin(userId)) {
            return interaction.reply({ content: "⛔ Chỉ Admin mới có quyền dừng stream của người khác!", ephemeral: true });
          }

          const engine = activeEngines.get(String(targetId));
          if (!engine || !engine.running) {
            return interaction.reply({ content: "⚪ Không tìm thấy luồng stream nào đang chạy.", ephemeral: true });
          }

          engine.stop();
          activeEngines.delete(String(targetId));
          return interaction.reply({
            content: `🛑 Đã dừng luồng stream của <@${targetId}>! Thời gian phiên: **${formatTimer(engine.counted_stream_seconds)}**`,
            ephemeral: true,
          });
        }

        if (sub === "status") {
          const engine = activeEngines.get(String(userId));
          const state = getUserState(userId);
          const isStreaming = Boolean(engine && engine.running);

          return interaction.reply({
            embeds: [
              new EmbedBuilder()
                .setTitle("📡 TRẠNG THÁI STREAM")
                .setColor(isStreaming ? 0x57f287 : 0xed4245)
                .addFields(
                  { name: "Trạng thái", value: isStreaming ? "🟢 **ĐANG PHÁT LIVE**" : "⚪ Ngoại tuyến", inline: true },
                  { name: "Người xem", value: `**${engine ? engine.getViewerCount() : 0}** viewers`, inline: true },
                  { name: "Thời gian phiên", value: `\`${engine ? formatTimer(engine.counted_stream_seconds) : "00:00:00"}\``, inline: true },
                  { name: "Tổng giờ trọn đời", value: `\`${state.total_stream_hours_claimed.toFixed(2)}h\``, inline: true }
                ),
            ],
            ephemeral: true,
          });
        }

        if (sub === "list") {
          if (!isAdmin(userId)) {
            return interaction.reply({ content: "⛔ Lệnh này chỉ dành cho Admin!", ephemeral: true });
          }
          const lines = [];
          for (const [uid, eng] of activeEngines.entries()) {
            if (eng.running) {
              lines.push(`• <@${uid}>: Phòng \`${eng.channel_id || "Auto"}\` | Viewers: **${eng.getViewerCount()}** | Uptime: **${formatTimer(eng.counted_stream_seconds)}**`);
            }
          }
          return interaction.reply({
            content: lines.length ? `🔴 **Các luồng đang chạy:**\n${lines.join("\n")}` : "⚪ Hiện không có luồng nào đang phát.",
            ephemeral: true,
          });
        }
      }

      if (commandName === "farm_games") {
        const state = getUserState(userId);
        if (!state.token || !state.cookie) {
          return interaction.reply({
            content: "❌ Bạn cần cài đặt cả **Token chính** và **Cookie cf_clearance** trước khi cày game (bấm `/setup`).",
            ephemeral: true,
          });
        }

        const count = interaction.options.getInteger("count");
        const hours = interaction.options.getNumber("hours") || 1.0;

        await interaction.deferReply({ ephemeral: true });
        activeFarms.set(String(userId), true);

        try {
          const app = new ApplicationController(null, getUserStateFile(userId));
          const result = await app.startHeadless(count, hours);
          activeFarms.delete(String(userId));

          if (result.success) {
            return interaction.editReply({
              content: `✅ **Cày Game Thành Công!**\n• Đã claim: **${result.accepted}/${result.total_requested}** tựa game\n• Giờ mỗi game: **${result.hours_per_game} giờ**\n• Tổng playtime: **${result.total_hours.toLocaleString()} giờ**`,
            });
          } else {
            return interaction.editReply({ content: `❌ Lỗi: \`${result.error}\`` });
          }
        } catch (exc) {
          activeFarms.delete(String(userId));
          return interaction.editReply({ content: `❌ Ngoại lệ: \`${exc.message || exc}\`` });
        }
      }

      if (commandName === "profile") {
        const state = getUserState(userId);
        if (!state.token) {
          return interaction.reply({ content: "❌ Bạn chưa thiết lập token! Gõ `/setup` trước.", ephemeral: true });
        }

        await interaction.deferReply({ ephemeral: true });
        try {
          const meRes = await fetch("https://discord.com/api/v9/users/@me", {
            headers: { authorization: state.token, "user-agent": USER_AGENT },
          });
          if (!meRes.ok) {
            return interaction.editReply({ content: "❌ Token không hợp lệ hoặc đã hết hạn!" });
          }
          const userObj = await meRes.json();
          const profRes = await fetch(
            `${USERS_URL}/${userObj.id}/profile?with_mutual_guilds=false&with_mutual_friends_count=false`,
            { headers: { authorization: state.token, "user-agent": USER_AGENT } }
          );

          if (profRes.ok) {
            const profData = await profRes.json();
            const badges = profData.badges || [];
            const embed = new EmbedBuilder()
              .setTitle(`Hồ sơ Discord: ${userObj.global_name || userObj.username}`)
              .setDescription(`Username: \`@${userObj.username}\` | ID: \`${userObj.id}\``)
              .setColor(0x5865f2);

            if (badges.length) {
              embed.addFields({
                name: `🏆 Huy hiệu (${badges.length})`,
                value: badges.map((b) => `• **${b.id}**: ${b.description}`).join("\n"),
              });
            } else {
              embed.addFields({ name: "🏆 Huy hiệu", value: "*(Chưa có huy hiệu công khai)*" });
            }

            return interaction.editReply({ embeds: [embed] });
          }
          return interaction.editReply({ content: "❌ Không thể tải thông tin profile từ Discord." });
        } catch (exc) {
          return interaction.editReply({ content: `❌ Lỗi: \`${exc.message || exc}\`` });
        }
      }

      if (commandName === "config") {
        const state = getUserState(userId);
        return interaction.reply({
          embeds: [
            new EmbedBuilder()
              .setTitle("⚙️ CẤU HÌNH CỦA BẠN")
              .setColor(0x5865f2)
              .addFields(
                { name: "Token Chính", value: maskToken(state.token), inline: false },
                { name: "Token Phụ (Alt)", value: maskToken(state.viewer_token), inline: false },
                { name: "Cookie cf_clearance", value: state.cookie ? "✅ *(Đã lưu)*" : "❌ *(Chưa có)*", inline: false },
                { name: "Phòng Voice", value: state.last_channel_id ? `\`${state.last_channel_id}\`` : "🎲 *(Tự động ngẫu nhiên)*", inline: false },
                { name: "Nguồn Video", value: state.stream_url ? `\`${state.stream_url}\`` : "📁 *(Mặc định)*", inline: false }
              ),
          ],
          ephemeral: true,
        });
      }

      if (commandName === "clear_config") {
        const p = getUserStateFile(userId);
        if (fs.existsSync(p)) {
          fs.unlinkSync(p);
        }
        return interaction.reply({ content: "🗑️ **Đã xóa toàn bộ dữ liệu cấu hình đã lưu của bạn!**", ephemeral: true });
      }

      if (commandName === "help") {
        return interaction.reply({
          embeds: [
            new EmbedBuilder()
              .setTitle("📖 DANH SÁCH LỆNH DISCORD BADGE MAXIMIZER")
              .setColor(0x5865f2)
              .setDescription(
                "• `/panel` — **Bảng Điều Khiển Nút Bấm Đầy Đủ** *(Khuyên dùng)*\n" +
                  "• `/setup` — Mở Popup cài đặt Token chính, phụ, cookie\n" +
                  "• `/stream start` — Bắt đầu phát Live Stream\n" +
                  "• `/stream play <url>` — Phát trực tiếp link YouTube hoặc video URL\n" +
                  "• `/stream stop` — Dừng phát Live Stream\n" +
                  "• `/stream status` — Xem trạng thái stream & viewers\n" +
                  "• `/farm_games` — Cày playtime tự động nhiều game\n" +
                  "• `/profile` — Kiểm tra các huy hiệu hiện có trên hồ sơ\n" +
                  "• `/config` — Xem lại cấu hình token đã lưu\n" +
                  "• `/clear_config` — Xóa sạch dữ liệu đã lưu"
              ),
          ],
          ephemeral: true,
        });
      }

      if (commandName === "admin") {
        if (!isAdmin(userId)) {
          return interaction.reply({ content: "⛔ Bạn không có quyền Admin!", ephemeral: true });
        }
        const sub = interaction.options.getSubcommand();

        if (sub === "panel") {
          return interaction.reply({
            embeds: [buildAdminPanelEmbed()],
            components: buildAdminPanelComponents(),
            ephemeral: true,
          });
        }

        if (sub === "stats") {
          return interaction.reply({ embeds: [buildAdminPanelEmbed()], ephemeral: true });
        }

        if (sub === "stop_all") {
          let count = 0;
          for (const [uid, eng] of activeEngines.entries()) {
            if (eng.running) {
              eng.stop();
              count++;
            }
          }
          activeEngines.clear();
          return interaction.reply({ content: `🚨 Đã dừng toàn bộ **${count}** luồng stream!`, ephemeral: true });
        }

        if (sub === "stop") {
          const user = interaction.options.getUser("user", true);
          const engine = activeEngines.get(String(user.id));
          if (!engine || !engine.running) {
            return interaction.reply({ content: `⚪ User <@${user.id}> không có luồng stream nào đang chạy.`, ephemeral: true });
          }
          engine.stop();
          activeEngines.delete(String(user.id));
          return interaction.reply({ content: `🛑 Đã dừng luồng của <@${user.id}>.`, ephemeral: true });
        }

        if (sub === "reset_user") {
          const user = interaction.options.getUser("user", true);
          const p = getUserStateFile(user.id);
          if (fs.existsSync(p)) fs.unlinkSync(p);
          if (activeEngines.has(String(user.id))) {
            activeEngines.get(String(user.id)).stop();
            activeEngines.delete(String(user.id));
          }
          return interaction.reply({ content: `🗑️ Đã reset dữ liệu và dừng tiến trình của <@${user.id}>.`, ephemeral: true });
        }

        if (sub === "list") {
          const lines = [];
          for (const [uid, eng] of activeEngines.entries()) {
            if (eng.running) {
              lines.push(`• <@${uid}>: Phòng \`${eng.channel_id || "Auto"}\` | Viewers: **${eng.getViewerCount()}**`);
            }
          }
          return interaction.reply({
            content: lines.length ? `🔴 **Các luồng đang chạy:**\n${lines.join("\n")}` : "⚪ Hiện không có luồng nào đang phát.",
            ephemeral: true,
          });
        }
      }
    }
  } catch (err) {
    console.error("❌ Interaction handler error:", err);
    try {
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({ content: `❌ Có lỗi xảy ra: ${err.message || err}`, ephemeral: true });
      }
    } catch {
      // Ignore
    }
  }
});

// Start the Bot if DISCORD_BOT_TOKEN is present
if (!process.env.DISCORD_BOT_TOKEN) {
  console.log("⚠️ [Bot] DISCORD_BOT_TOKEN chưa được cấu hình trong .env.");
  console.log("👉 Vui lòng tạo file .env từ .env.example và điền Bot Token để khởi chạy bot!");
} else {
  client.login(process.env.DISCORD_BOT_TOKEN).catch((err) => {
    console.error("❌ [Bot] Login failed:", err.message || err);
  });
}
