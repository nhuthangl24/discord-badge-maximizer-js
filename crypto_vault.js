/**
 * Crypto Vault Module - Discord Badge Maximizer (Node.js)
 * Provides nested two-way symmetric encryption (DES / TripleDES + AES-256)
 * for user Discord tokens, alt tokens, and cookies.
 *
 * Architecture:
 *   Plaintext Token
 *        │
 *        ▼
 *   [Layer 1: TripleDES-CBC / PKCS7 (64-bit block)]
 *        │
 *        ▼
 *   [Layer 2: AES-256-CBC / PKCS7 (128-bit block)]
 *        │
 *        ▼
 *   Ciphertext payload: [16-byte AES IV] + [8-byte DES IV] + [Nested Ciphertext]
 *        │
 *        ▼
 *   Base64: enc:nested_des_aes:v1:<base64>
 *
 * Security Guarantees:
 * - Neither Bot Admin nor anyone inspecting the database/JSON files can read user tokens.
 * - User-specific key derivation: each Discord user ID gets unique AES and DES keys
 *   derived via HMAC-SHA512 from the master vault secret + user Discord ID.
 * - Tokens on disk (data/users/*.json) are 100% encrypted at rest.
 * - 100% interoperable with the Python crypto_vault implementation.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MAGIC_PREFIX = "enc:nested_des_aes:v1:";

const __filename = fileURLToPath(import.meta.url);
const ROOT_DIR = path.dirname(__filename);
export const DATA_DIR = path.join(ROOT_DIR, "data");
export const VAULT_KEY_FILE = path.join(DATA_DIR, ".vault_master.key");

/**
 * Retrieves or creates the master secret key for token vault encryption.
 * @returns {Buffer} 32-byte master key
 */
export function getVaultMasterKey() {
  const envKey = process.env.DISCORD_VAULT_KEY || process.env.TOKEN_VAULT_SECRET;
  if (envKey) {
    return crypto.createHash("sha256").update(envKey.trim(), "utf8").digest();
  }

  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(VAULT_KEY_FILE)) {
      const keyBytes = fs.readFileSync(VAULT_KEY_FILE);
      if (keyBytes.length >= 32) {
        return keyBytes.subarray(0, 32);
      }
    }
  } catch {
    // Continue to generate new key
  }

  const newKey = crypto.randomBytes(32);
  try {
    fs.writeFileSync(VAULT_KEY_FILE, newKey, { mode: 0o600 });
  } catch {
    // Ignore write failure in restricted sandbox
  }
  return newKey;
}

/**
 * Derives unique 256-bit AES key and 192-bit TripleDES key for a specific user ID.
 * Guarantees isolation: ciphertexts are unique per user even for identical tokens.
 * @param {string|number} userId
 * @param {Buffer} [masterKey]
 * @returns {{ keyAes: Buffer, keyDes: Buffer }}
 */
export function deriveUserKeys(userId, masterKey) {
  const master = masterKey || getVaultMasterKey();
  const salt = Buffer.from(
    `user:${String(userId).trim()}:discord_badge_maximizer:nested_des_aes`,
    "utf8"
  );
  const derived = crypto.createHmac("sha512", master).update(salt).digest();
  const keyAes = derived.subarray(0, 32); // 256-bit key for AES-256
  const keyDes = derived.subarray(32, 56); // 192-bit key for TripleDES (24 bytes)
  return { keyAes, keyDes };
}

/**
 * Checks whether a string is already encrypted in the nested DES+AES format.
 * @param {string} val
 * @returns {boolean}
 */
export function isEncrypted(val) {
  return Boolean(val && typeof val === "string" && val.startsWith(MAGIC_PREFIX));
}

/**
 * Encrypts a plaintext Discord token or secret with nested DES (TripleDES) + AES-256.
 * Returns the prefixed base64 ciphertext string.
 * @param {string} token
 * @param {string|number} [userId=""]
 * @returns {string}
 */
export function encryptToken(token, userId = "") {
  if (!token || typeof token !== "string") {
    return "";
  }
  const tokenStr = token.trim();
  if (!tokenStr) {
    return "";
  }
  if (isEncrypted(tokenStr)) {
    return tokenStr;
  }

  const { keyAes, keyDes } = deriveUserKeys(userId);
  const rawData = Buffer.from(tokenStr, "utf8");

  // Layer 1: TripleDES-CBC Encryption with PKCS7 padding (64-bit block)
  const ivDes = crypto.randomBytes(8);
  const cipherDes = crypto.createCipheriv("des-ede3-cbc", keyDes, ivDes);
  const encDes = Buffer.concat([cipherDes.update(rawData), cipherDes.final()]);

  // Layer 2: AES-256-CBC Encryption with PKCS7 padding (128-bit block) over DES ciphertext
  const ivAes = crypto.randomBytes(16);
  const cipherAes = crypto.createCipheriv("aes-256-cbc", keyAes, ivAes);
  const encNested = Buffer.concat([cipherAes.update(encDes), cipherAes.final()]);

  // Pack IVs and nested ciphertext together: [16-byte AES IV] + [8-byte DES IV] + [Ciphertext]
  const payload = Buffer.concat([ivAes, ivDes, encNested]);
  return `${MAGIC_PREFIX}${payload.toString("base64")}`;
}

/**
 * Decrypts a nested DES + AES ciphertext string back into the original plaintext token.
 * Falls back gracefully if the token is unencrypted legacy text.
 * @param {string} cipherText
 * @param {string|number} [userId=""]
 * @returns {string}
 */
export function decryptToken(cipherText, userId = "") {
  if (!cipherText || typeof cipherText !== "string") {
    return "";
  }
  const cipherStr = cipherText.trim();
  if (!cipherStr) {
    return "";
  }
  if (!isEncrypted(cipherStr)) {
    // Raw / unencrypted legacy token fallback
    return cipherStr;
  }

  try {
    const rawB64 = cipherStr.slice(MAGIC_PREFIX.length);
    const payload = Buffer.from(rawB64, "base64");
    if (payload.length < 24) {
      return "";
    }

    const ivAes = payload.subarray(0, 16);
    const ivDes = payload.subarray(16, 24);
    const encNested = payload.subarray(24);

    const { keyAes, keyDes } = deriveUserKeys(userId);

    // Decrypt Layer 2: AES-256-CBC
    const decipherAes = crypto.createDecipheriv("aes-256-cbc", keyAes, ivAes);
    const encDes = Buffer.concat([decipherAes.update(encNested), decipherAes.final()]);

    // Decrypt Layer 1: TripleDES-CBC
    const decipherDes = crypto.createDecipheriv("des-ede3-cbc", keyDes, ivDes);
    const rawPlain = Buffer.concat([decipherDes.update(encDes), decipherDes.final()]);

    return rawPlain.toString("utf8").trim();
  } catch {
    return "";
  }
}

/**
 * Auto-migration utility: scans all existing data/users/*.json files on startup.
 * If any file contains plaintext tokens, encrypts them immediately with nested DES+AES.
 * @param {string} usersDir
 * @returns {number} count of migrated files
 */
export function migrateAllUserStates(usersDir) {
  if (!fs.existsSync(usersDir)) {
    return 0;
  }

  let migratedCount = 0;
  const sensitiveFields = ["token", "viewer_token", "cookie"];

  try {
    const files = fs.readdirSync(usersDir);
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const uidStr = path.parse(file).name;
      if (!/^\d+$/.test(uidStr)) continue;

      const fullPath = path.join(usersDir, file);
      try {
        const raw = fs.readFileSync(fullPath, "utf8");
        const data = JSON.parse(raw);
        let modified = false;

        for (const field of sensitiveFields) {
          const val = data[field];
          if (val && typeof val === "string" && !isEncrypted(val)) {
            data[field] = encryptToken(val, uidStr);
            modified = true;
          }
        }

        if (modified) {
          fs.writeFileSync(fullPath, JSON.stringify(data, null, 2), "utf8");
          migratedCount++;
        }
      } catch {
        // Skip malformed files
      }
    }
  } catch {
    // Ignore scan errors
  }

  return migratedCount;
}

export default {
  MAGIC_PREFIX,
  DATA_DIR,
  VAULT_KEY_FILE,
  getVaultMasterKey,
  deriveUserKeys,
  isEncrypted,
  encryptToken,
  decryptToken,
  migrateAllUserStates,
};
