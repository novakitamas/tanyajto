import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

// ============================================================
// SETTINGS
// ============================================================

const BOT_TOKEN = "9026012194:AAEfT7ZGeCII_AIjdHM7iPqDVDq8dNPpe6o";

// Password every user types in Telegram after /start (12+ characters).
const SECRET_PASSWORD = "1234567891011";

// First admin password for "/admin PASSWORD". It is only used to create the
// saved (hashed) admin password on the first start. After that, change the
// password in Telegram with "/adminp CURRENT NEW".
const INITIAL_ADMIN_PASSWORD = "piFc03elUtpLxdqc";

// ============================================================

// Optional: restrict access to specific numeric Telegram user IDs.
// Example: const ALLOWED_USER_IDS = [123456789];
// Leave empty to allow anyone who knows your secret password.
const ALLOWED_USER_IDS = [];

const SITE_ORIGIN = "https://rak.dzsula.xyz";
const LOGIN_PAGE_URL = `${SITE_ORIGIN}/dashboard/login`;
const LOGIN_URL = `${LOGIN_PAGE_URL}?/login`;
const PAGE_URL = `${SITE_ORIGIN}/dashboard/personnel-manager/gateways`;
const TARGET_URL = `${PAGE_URL}?/toggle`;

const COOKIE_NAME = "AuthorizationToken";
const DEFAULT_TOKEN_LIFETIME_MS = 4 * 60 * 60 * 1000;
const EXPIRY_MARGIN_MS = 60 * 1000;
const RETRY_DELAY_MS = 60 * 1000;
const BAD_PASSWORD_DELAY_MS = 60 * 60 * 1000;
const PENDING_TIMEOUT_MS = 5 * 60 * 1000;
const LOCKOUT_DURATION_MS = 5 * 60 * 1000;
const MAX_PASSWORD_ATTEMPTS = 5;
const TOGGLE_COOLDOWN_MS = 3000;
const MAX_MESSAGE_AGE_SECONDS = 60;

const MENU = {
  keyboard: [[{ text: "toggle" }]],
  resize_keyboard: true,
  is_persistent: true,
};

const HIDE_MENU = { remove_keyboard: true };

const KNOWN_COMMANDS = new Set([
  "start", "admin", "logout", "help", "token", "switch",
  "accounts", "adminp", "cancel",
]);

// In-memory state (never saved).
const passwordAttempts = new Map();
const adminAttempts = new Map();
const pending = new Map(); // userId -> { type, username, startedAt }
const accountSessions = new Map(); // account id -> { cookie, expiresAt }
const accountBlockedUntil = new Map();
const accountLogins = new Map();

let lastToggleAt = 0;
let stopping = false;

// Saved state. Passwords and tokens are stored encrypted (AES-256-GCM)
// with a random key kept in toggle-bot.key. Keep both files private.
const AUTH_DIR =
  process.env.AUTH_DIR || fileURLToPath(new URL(".", import.meta.url));
const DATA_FILE = join(AUTH_DIR, "toggle-bot-data.json");
const DATA_TEMP_FILE = join(AUTH_DIR, "toggle-bot-data.json.tmp");
const KEY_FILE = join(AUTH_DIR, "toggle-bot.key");
const LEGACY_AUTH_FILE = join(AUTH_DIR, "toggle-bot-auth.json");

const data = {
  admins: [],
  users: [],
  modes: {},
  userTokens: {},
  accounts: [],
  adminPasswordHash: "",
};

let encryptionKey = null;

function getKey() {
  if (encryptionKey) return encryptionKey;

  try {
    const hex = readFileSync(KEY_FILE, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("invalid");
    encryptionKey = Buffer.from(hex, "hex");
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw new Error(
        "toggle-bot.key is invalid. Restore it, or delete it " +
          "(saved accounts and tokens then become unreadable)."
      );
    }

    const key = randomBytes(32);
    writeFileSync(KEY_FILE, key.toString("hex"), {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    encryptionKey = key;
  }

  return encryptionKey;
}

function encryptText(plain) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);

  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
}

function safeDecrypt(payload) {
  try {
    const raw = Buffer.from(payload, "base64");
    const decipher = createDecipheriv("aes-256-gcm", getKey(), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));

    return Buffer.concat([
      decipher.update(raw.subarray(28)),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

function hashAdminPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32);

  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function adminPasswordMatches(input) {
  const [scheme, saltHex, hashHex] = String(data.adminPasswordHash).split("$");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;

  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(input, Buffer.from(saltHex, "hex"), expected.length);

  return timingSafeEqual(actual, expected);
}

function secretMatches(input) {
  const hash = (value) => createHash("sha256").update(value, "utf8").digest();

  return timingSafeEqual(hash(input), hash(SECRET_PASSWORD));
}

// Changing BOT_TOKEN or SECRET_PASSWORD logs out normal users.
function usersFingerprint() {
  return createHash("sha256")
    .update(JSON.stringify([BOT_TOKEN, SECRET_PASSWORD]))
    .digest("hex");
}

function validIds(list) {
  return Array.isArray(list)
    ? list.filter((id) => Number.isSafeInteger(id) && id > 0)
    : [];
}

function loadData() {
  let stored = null;

  try {
    stored = JSON.parse(readFileSync(DATA_FILE, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw new Error(
        "Could not read toggle-bot-data.json. " +
          "Fix or delete that file, then restart the bot."
      );
    }
  }

  if (!stored) {
    // First start of this version: keep users from the old auth file.
    try {
      const legacy = JSON.parse(readFileSync(LEGACY_AUTH_FILE, "utf8"));

      if (legacy.version === 1 && legacy.fingerprint === usersFingerprint()) {
        data.users = validIds(legacy.userIds);
      }
    } catch {
      // No usable legacy file.
    }

    return;
  }

  if (stored.version !== 4) {
    throw new Error("Unsupported toggle-bot-data.json. Delete it and restart.");
  }

  data.admins = validIds(stored.admins);
  data.adminPasswordHash =
    typeof stored.adminPasswordHash === "string" ? stored.adminPasswordHash : "";

  data.accounts = (Array.isArray(stored.accounts) ? stored.accounts : []).filter(
    (a) =>
      typeof a?.id === "string" &&
      typeof a?.username === "string" &&
      typeof a?.password === "string"
  );

  const usersValid = stored.usersFingerprint === usersFingerprint();
  data.users = usersValid ? validIds(stored.users) : [];

  for (const [key, value] of Object.entries(stored.modes || {})) {
    const id = Number(key);
    const allowed = data.admins.includes(id) || data.users.includes(id);
    if (allowed && (value === "token" || value === "account")) {
      data.modes[key] = value;
    }
  }

  for (const [key, value] of Object.entries(stored.userTokens || {})) {
    const id = Number(key);
    const allowed = data.admins.includes(id) || data.users.includes(id);
    if (allowed && typeof value === "string") data.userTokens[key] = value;
  }
}

function saveData() {
  const stored = { version: 4, usersFingerprint: usersFingerprint(), ...data };

  writeFileSync(DATA_TEMP_FILE, JSON.stringify(stored, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });

  renameSync(DATA_TEMP_FILE, DATA_FILE);
}

// Applies a change and saves it. Rolls back if saving fails.
function mutate(change) {
  const snapshot = structuredClone(data);

  try {
    change(data);
    saveData();
    return true;
  } catch {
    Object.assign(data, snapshot);
    return false;
  }
}

function validateConfiguration() {
  if (Number(process.versions.node.split(".")[0]) < 22) {
    throw new Error("Please install Node.js 22 or newer.");
  }

  if (!/^\d+:[A-Za-z0-9_-]+$/.test(BOT_TOKEN)) {
    throw new Error("BOT_TOKEN has an invalid format.");
  }

  if (!SECRET_PASSWORD || SECRET_PASSWORD.length < 12) {
    throw new Error("SECRET_PASSWORD must be at least 12 characters.");
  }

  if (!ALLOWED_USER_IDS.every((id) => Number.isSafeInteger(id) && id > 0)) {
    throw new Error("ALLOWED_USER_IDS must contain numeric user IDs.");
  }
}

function initialize() {
  validateConfiguration();
  getKey();
  loadData();

  if (!data.adminPasswordHash) {
    if (!INITIAL_ADMIN_PASSWORD || INITIAL_ADMIN_PASSWORD.length < 12) {
      throw new Error("INITIAL_ADMIN_PASSWORD must be at least 12 characters.");
    }

    const ok = mutate((d) => {
      d.adminPasswordHash = hashAdminPassword(INITIAL_ADMIN_PASSWORD);
    });

    if (!ok) throw new Error("Could not write toggle-bot-data.json.");
  }
}

const isAdmin = (id) => data.admins.includes(id);
const isAuthed = (id) => isAdmin(id) || data.users.includes(id);

function isValidCookieValue(value) {
  return /^[A-Za-z0-9%._~+\/=-]+$/.test(value);
}

function parseUserToken(raw) {
  let value = String(raw).trim();

  if (value.toLowerCase().startsWith(`${COOKIE_NAME.toLowerCase()}=`)) {
    value = value.slice(COOKIE_NAME.length + 1);
  }

  value = value.split(";")[0].trim().replace(/^"(.*)"$/, "$1");

  if (value.length < 16 || value.length > 4096 || !isValidCookieValue(value)) {
    return null;
  }

  return value;
}

function lockSecondsLeft(map, userId, now) {
  const record = map.get(userId);
  if (!record) return 0;

  if (record.lockedUntil > now) {
    return Math.ceil((record.lockedUntil - now) / 1000);
  }

  if (record.lockedUntil !== 0) map.delete(userId);
  return 0;
}

function registerFailure(map, userId, now) {
  const record = map.get(userId) || { failures: 0, lockedUntil: 0, updatedAt: now };

  record.failures += 1;
  record.updatedAt = now;

  if (record.failures >= MAX_PASSWORD_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_DURATION_MS;
  }

  map.set(userId, record);
  return record.lockedUntil > now;
}

async function telegram(method, payload = {}, timeoutMs = 15000) {
  const response = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    }
  );

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error("Telegram returned an unreadable response.");
  }

  if (!response.ok || !result.ok) {
    const error = new Error(
      `Telegram API error ${result.error_code || response.status}.`
    );

    error.code = result.error_code || response.status;
    error.retryAfter = result.parameters?.retry_after;

    throw error;
  }

  return result.result;
}

// replyMarkup is optional: when omitted, the current keyboard stays as it is.
function sendMessage(chatId, text, replyMarkup) {
  const payload = { chat_id: chatId, text, disable_web_page_preview: true };
  if (replyMarkup) payload.reply_markup = replyMarkup;

  return telegram("sendMessage", payload);
}

async function quietly(promise) {
  try {
    await promise;
  } catch {
    // Best effort only.
  }
}

// Used for messages that contain passwords or tokens.
function deleteMessageQuietly(chatId, messageId) {
  return quietly(
    telegram("deleteMessage", { chat_id: chatId, message_id: messageId })
  );
}

function describeUser(from) {
  const name =
    [from.first_name, from.last_name].filter(Boolean).join(" ") || "Unknown";

  return `${name}${from.username ? ` (@${from.username})` : ""}, ID ${from.id}`;
}

function extractAuthCookie(response) {
  for (const line of response.headers.getSetCookie()) {
    if (!line.startsWith(`${COOKIE_NAME}=`)) continue;

    const value = line
      .split(";")[0]
      .slice(COOKIE_NAME.length + 1)
      .trim();

    if (!value || !isValidCookieValue(value)) return null;

    let expiresAt = Date.now() + DEFAULT_TOKEN_LIFETIME_MS;

    const maxAge = line.match(/;\s*max-age=(\d+)/i);
    const expires = line.match(/;\s*expires=([^;]+)/i);

    if (maxAge) {
      expiresAt = Date.now() + Number(maxAge[1]) * 1000;
    } else if (expires && Number.isFinite(Date.parse(expires[1]))) {
      expiresAt = Date.parse(expires[1]);
    }

    return { value, expiresAt: expiresAt - EXPIRY_MARGIN_MS };
  }

  return null;
}

// One login attempt on the website. Messages never contain the password.
async function loginToSite(username, password) {
  try {
    const response = await fetch(LOGIN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "x-sveltekit-action": "true",
        Origin: SITE_ORIGIN,
        Referer: LOGIN_PAGE_URL,
      },
      body: new URLSearchParams({ redirectTo: "", username, password }),
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    let result = null;

    try {
      result = JSON.parse(await response.text());
    } catch {
      // Non-JSON response; handled below.
    }

    if (result?.type === "failure" || result?.type === "error") {
      return {
        ok: false,
        wrongCredentials: result.type === "failure",
        message:
          result.type === "failure"
            ? "The website rejected the username or password."
            : "The website reported a server error during login.",
      };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        wrongCredentials: true,
        message: "The website rejected the username or password.",
      };
    }

    if (response.status >= 400) {
      return {
        ok: false,
        wrongCredentials: false,
        message: `The website returned HTTP ${response.status} during login.`,
      };
    }

    const cookie = extractAuthCookie(response);

    if (!cookie) {
      return {
        ok: false,
        wrongCredentials: false,
        message:
          `The website answered HTTP ${response.status} but did not ` +
          "send a login cookie. The login flow may have changed.",
      };
    }

    return { ok: true, cookie };
  } catch {
    return {
      ok: false,
      wrongCredentials: false,
      message: "The login request timed out or a network error occurred.",
    };
  }
}

// Logs in with a saved account (one attempt, shared between callers).
function loginAccount(account) {
  const blockedUntil = accountBlockedUntil.get(account.id) || 0;

  if (blockedUntil > Date.now()) {
    const seconds = Math.ceil((blockedUntil - Date.now()) / 1000);

    return Promise.resolve({
      ok: false,
      message: `The last website login failed. Next attempt possible in ${seconds} seconds.`,
    });
  }

  if (accountLogins.has(account.id)) return accountLogins.get(account.id);

  const promise = (async () => {
    const password = safeDecrypt(account.password);

    if (password === null) {
      return {
        ok: false,
        message: "The saved account could not be decrypted. Re-add it with /accounts.",
      };
    }

    const result = await loginToSite(account.username, password);

    if (result.ok) {
      accountBlockedUntil.delete(account.id);
      accountSessions.set(account.id, {
        cookie: result.cookie.value,
        expiresAt: result.cookie.expiresAt,
      });

      return { ok: true, cookie: result.cookie.value };
    }

    accountBlockedUntil.set(
      account.id,
      Date.now() + (result.wrongCredentials ? BAD_PASSWORD_DELAY_MS : RETRY_DELAY_MS)
    );

    return { ok: false, message: result.message };
  })().finally(() => accountLogins.delete(account.id));

  accountLogins.set(account.id, promise);
  return promise;
}

async function ensureAccountCookie(account) {
  const cached = accountSessions.get(account.id);

  if (cached && cached.expiresAt > Date.now() + 30 * 1000) {
    return { ok: true, cookie: cached.cookie };
  }

  return loginAccount(account);
}

// Returns { text, sessionInvalid }. A toggle is never retried automatically.
async function sendToggleRequest(cookie) {
  const checkBeforeRetry =
    " Check the website before trying again. No automatic retry was made.";

  try {
    const response = await fetch(TARGET_URL, {
      method: "POST",
      headers: {
        Accept: "application/json, */*;q=0.9",
        "x-sveltekit-action": "true",
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: `${COOKIE_NAME}=${cookie}`,
        Origin: SITE_ORIGIN,
        Referer: PAGE_URL,
      },
      body: new URLSearchParams(),
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    const responseText = await response.text();

    if (
      response.status === 401 ||
      response.status === 403 ||
      (response.status >= 300 && response.status < 400)
    ) {
      return {
        sessionInvalid: true,
        text:
          `The website rejected the token (HTTP ${response.status}). ` +
          "The toggle was not performed.",
      };
    }

    if (!response.ok) {
      return {
        sessionInvalid: false,
        text: `Server returned HTTP ${response.status}.` + checkBeforeRetry,
      };
    }

    if (response.status === 204 || !responseText.trim()) {
      return {
        sessionInvalid: false,
        text:
          `Request accepted: HTTP ${response.status}. ` +
          "No resulting state was returned. Check the website.",
      };
    }

    let result;

    try {
      result = JSON.parse(responseText);
    } catch {
      return {
        sessionInvalid: false,
        text:
          `Received HTTP ${response.status}, but not JSON. ` +
          "The toggle outcome is unconfirmed." +
          checkBeforeRetry,
      };
    }

    if (result?.type === "failure" || result?.type === "error") {
      return {
        sessionInvalid: false,
        text:
          `The server action reported ${result.type} ` +
          `(status ${Number(result.status) || response.status}).` +
          checkBeforeRetry,
      };
    }

    if (result?.type === "redirect") {
      return {
        sessionInvalid: false,
        text:
          "The server action returned a redirect. " +
          "The toggle outcome is unconfirmed." +
          checkBeforeRetry,
      };
    }

    if (result?.type === "success") {
      return {
        sessionInvalid: false,
        text:
          "The server reported action success. " +
          "Check the website for the resulting state.",
      };
    }

    return {
      sessionInvalid: false,
      text:
        `Received JSON: HTTP ${response.status}. ` +
        "Check the website for the resulting state.",
    };
  } catch {
    return {
      sessionInvalid: false,
      text:
        "The request timed out or a network error occurred. " +
        "It may already have toggled. Check the website before " +
        "trying again. No automatic retry was made.",
    };
  }
}

// ---------------------------------------------------------------
// Accounts view (usernames only, never passwords)
// ---------------------------------------------------------------

function shorten(text, max = 28) {
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function buildAccountsView() {
  const count = data.accounts.length;

  const text = count
    ? `Website accounts (${count}):\n` +
      data.accounts
        .map((a, i) => `${i + 1}. ${a.username}${i === 0 ? " (default)" : ""}`)
        .join("\n") +
      "\n\nThe first account is used by default."
    : "No website accounts yet. Add one with the button below.";

  const rows = data.accounts.map((a) => [
    { text: `Delete ${shorten(a.username)}`, callback_data: `d:${a.id}` },
  ]);

  rows.push([{ text: "Add new account", callback_data: "a" }]);

  return { text, reply_markup: { inline_keyboard: rows } };
}

function sendAccountsView(chatId) {
  const view = buildAccountsView();
  return sendMessage(chatId, view.text, view.reply_markup);
}

function editMessage(chatId, messageId, text, replyMarkup) {
  return quietly(
    telegram("editMessageText", {
      chat_id: chatId,
      message_id: messageId,
      text,
      reply_markup: replyMarkup,
    })
  );
}

async function addAccount(chatId, username, password) {
  await sendMessage(chatId, "Checking the login with the website...");

  const result = await loginToSite(username, password);

  if (!result.ok) {
    await sendMessage(
      chatId,
      "Nothing was saved. " +
        (result.wrongCredentials
          ? "The website rejected that username or password."
          : `${result.message} Try again later.`)
    );
    return;
  }

  if (data.accounts.some((a) => a.username === username)) {
    await sendMessage(chatId, "That account already exists. Nothing was saved.");
    return;
  }

  const id = randomBytes(4).toString("hex");
  const saved = mutate((d) => {
    d.accounts.push({ id, username, password: encryptText(password) });
  });

  if (!saved) {
    await sendMessage(
      chatId,
      "Could not save the account. Check that the bot's folder is writable."
    );
    return;
  }

  accountSessions.set(id, {
    cookie: result.cookie.value,
    expiresAt: result.cookie.expiresAt,
  });

  await sendMessage(chatId, `Account "${username}" added.`);
  await sendAccountsView(chatId);
}

// ---------------------------------------------------------------
// Callback buttons (admins only)
// ---------------------------------------------------------------

async function handleCallback(query) {
  const answer = (text) =>
    quietly(
      telegram("answerCallbackQuery", {
        callback_query_id: query.id,
        ...(text ? { text } : {}),
      })
    );

  const userId = query.from?.id;
  const message = query.message;

  if (
    !userId ||
    query.from.is_bot ||
    message?.chat?.type !== "private" ||
    message.chat.id !== userId ||
    (ALLOWED_USER_IDS.length > 0 && !ALLOWED_USER_IDS.includes(userId))
  ) {
    await answer();
    return;
  }

  if (!isAdmin(userId)) {
    await answer("Admins only.");
    return;
  }

  const payload = typeof query.data === "string" ? query.data : "";

  if (!/^(a|c|[dy]:[0-9a-f]{8})$/.test(payload)) {
    await answer();
    return;
  }

  const chatId = message.chat.id;
  const [action, id] = payload.split(":");
  const showList = () => {
    const view = buildAccountsView();
    return editMessage(chatId, message.message_id, view.text, view.reply_markup);
  };

  if (action === "a") {
    pending.set(userId, { type: "add_username", username: "", startedAt: Date.now() });
    await answer();
    await sendMessage(
      chatId,
      "Send the username of the new website account. Send /cancel to abort."
    );
    return;
  }

  if (action === "c") {
    await answer();
    await showList();
    return;
  }

  const account = data.accounts.find((a) => a.id === id);

  if (!account) {
    await answer("That account no longer exists.");
    await showList();
    return;
  }

  if (action === "d") {
    await answer();
    await editMessage(
      chatId,
      message.message_id,
      `Delete the account "${account.username}"? This cannot be undone.`,
      {
        inline_keyboard: [
          [
            { text: "Yes, delete", callback_data: `y:${account.id}` },
            { text: "Cancel", callback_data: "c" },
          ],
        ],
      }
    );
    return;
  }

  const removed = mutate((d) => {
    d.accounts = d.accounts.filter((a) => a.id !== account.id);
  });

  if (removed) {
    accountSessions.delete(account.id);
    accountBlockedUntil.delete(account.id);
  }

  await answer(removed ? "Deleted." : "Could not save the change.");
  await showList();
}

// ---------------------------------------------------------------
// Messages
// ---------------------------------------------------------------

function helpText(userId) {
  const lines = [
    "Commands:",
    "/token - use your own website token (send /token YOUR_TOKEN to set or replace it)",
    "/switch - go back to the website account",
  ];

  if (isAdmin(userId)) {
    lines.push(
      "/accounts - manage the website accounts",
      "/adminp CURRENT NEW - change the admin password"
    );
  }

  return lines.join("\n");
}

async function handleAdminLogin(message, command, now) {
  const chatId = message.chat.id;
  const userId = message.from.id;

  // The message contains a password: remove it from the chat.
  await deleteMessageQuietly(chatId, message.message_id);

  if (command.args.length !== 1) {
    await sendMessage(chatId, "Usage: /admin PASSWORD");
    return;
  }

  const wait = lockSecondsLeft(adminAttempts, userId, now);

  if (wait) {
    await sendMessage(chatId, `Too many incorrect passwords. Try again in ${wait} seconds.`);
    return;
  }

  if (!adminPasswordMatches(command.args[0])) {
    const locked = registerFailure(adminAttempts, userId, now);

    await sendMessage(
      chatId,
      locked
        ? "Too many incorrect passwords. Locked for 5 minutes."
        : "Incorrect admin password."
    );
    return;
  }

  adminAttempts.delete(userId);

  if (isAdmin(userId)) {
    await sendMessage(chatId, "You are already an admin.", MENU);
    return;
  }

  const saved = mutate((d) => {
    d.admins.push(userId);
  });

  if (!saved) {
    await sendMessage(
      chatId,
      "The password was correct, but the change could not be saved. " +
        "Check that the bot's folder is writable."
    );
    return;
  }

  await sendMessage(
    chatId,
    "You are now an admin. Send /help to see your commands.",
    MENU
  );

  for (const adminId of data.admins) {
    if (adminId === userId) continue;

    await quietly(
      sendMessage(adminId, `A new admin logged in: ${describeUser(message.from)}.`)
    );
  }
}

async function handleSecretPassword(message, text, now) {
  const chatId = message.chat.id;
  const userId = message.from.id;
  const wait = lockSecondsLeft(passwordAttempts, userId, now);

  if (wait) {
    await sendMessage(
      chatId,
      `Too many incorrect passwords. Try again in ${wait} seconds.`,
      HIDE_MENU
    );
    return;
  }

  if (!text) {
    await sendMessage(chatId, "Enter the secret password as a text message:", HIDE_MENU);
    return;
  }

  await deleteMessageQuietly(chatId, message.message_id);

  if (!secretMatches(text)) {
    const locked = registerFailure(passwordAttempts, userId, now);

    await sendMessage(
      chatId,
      locked
        ? "Too many incorrect passwords. Locked for 5 minutes."
        : "Incorrect password. Try again:",
      HIDE_MENU
    );
    return;
  }

  passwordAttempts.delete(userId);

  const saved = mutate((d) => {
    if (!d.users.includes(userId)) d.users.push(userId);
  });

  if (!saved) {
    await sendMessage(
      chatId,
      "The password was correct, but authentication could not be saved. " +
        "Check that the bot's folder is writable, then try again.",
      HIDE_MENU
    );
    return;
  }

  await sendMessage(
    chatId,
    "Authenticated. Your login does not expire. Use toggle below. " +
      "Send /help for commands.",
    MENU
  );
}

async function handlePendingInput(message, text, entry, now) {
  const chatId = message.chat.id;
  const userId = message.from.id;

  if (!text) {
    await sendMessage(chatId, "Please send text, or /cancel to abort.");
    return;
  }

  if (entry.type === "token") {
    await deleteMessageQuietly(chatId, message.message_id);
    const token = parseUserToken(text);

    if (!token) {
      await sendMessage(
        chatId,
        "That does not look like a valid token. Send it again, or /cancel."
      );
      return;
    }

    pending.delete(userId);
    await saveUserToken(chatId, userId, token);
    return;
  }

  if (!isAdmin(userId)) {
    pending.delete(userId);
    return;
  }

  if (entry.type === "add_username") {
    const username = text.trim();

    if (!username || username.length > 100 || /[\r\n]/.test(username)) {
      await sendMessage(chatId, "Invalid username. Send another one, or /cancel.");
      return;
    }

    if (data.accounts.some((a) => a.username === username)) {
      await sendMessage(chatId, "That username already exists. Send another one, or /cancel.");
      return;
    }

    entry.type = "add_password";
    entry.username = username;
    entry.startedAt = now;

    await sendMessage(
      chatId,
      `Now send the password for "${username}". The bot will try to delete your message. Send /cancel to abort.`
    );
    return;
  }

  // add_password
  await deleteMessageQuietly(chatId, message.message_id);
  pending.delete(userId);

  if (text.length > 200) {
    await sendMessage(chatId, "That password is too long. Nothing was saved.");
    return;
  }

  await addAccount(chatId, entry.username, text);
}

async function saveUserToken(chatId, userId, token) {
  let saved = false;

  try {
    saved = mutate((d) => {
      d.userTokens[String(userId)] = encryptText(token);
      d.modes[String(userId)] = "token";
    });
  } catch {
    saved = false;
  }

  await sendMessage(
    chatId,
    saved
      ? "Token saved. Your token is used now. Send /switch to go back to the website account."
      : "Could not save the token. Check that the bot's folder is writable.",
    MENU
  );
}

async function handleToggle(chatId, userId, now) {
  if (now - lastToggleAt < TOGGLE_COOLDOWN_MS) {
    await sendMessage(chatId, "Please wait a few seconds before another toggle.", MENU);
    return;
  }

  lastToggleAt = now;

  let cookie;
  let label;
  let account = null;

  if (data.modes[String(userId)] === "token") {
    const encrypted = data.userTokens[String(userId)];
    cookie = encrypted ? safeDecrypt(encrypted) : null;
    label = "your token";

    if (!cookie) {
      await sendMessage(
        chatId,
        "No usable token is saved. Send /token YOUR_TOKEN, or /switch to use the website account.",
        MENU
      );
      return;
    }
  } else {
    account = data.accounts[0];
    label = "account";

    if (!account) {
      await sendMessage(
        chatId,
        "No website account is configured yet. An admin must add one with /accounts.",
        MENU
      );
      return;
    }

    const login = await ensureAccountCookie(account);

    if (!login.ok) {
      await sendMessage(
        chatId,
        `Could not log in to the website. ${login.message} The toggle was not performed.`,
        MENU
      );
      return;
    }

    cookie = login.cookie;
  }

  const result = await sendToggleRequest(cookie);

  if (result.sessionInvalid) {
    if (account) {
      accountSessions.delete(account.id);
      const fresh = await loginAccount(account);

      await sendMessage(
        chatId,
        fresh.ok
          ? `${result.text} A new login was fetched. Press toggle again.`
          : `${result.text} ${fresh.message}`,
        MENU
      );
    } else {
      await sendMessage(
        chatId,
        `${result.text} Send /token NEW_TOKEN to replace it, or /switch to use the website account.`,
        MENU
      );
    }

    return;
  }

  // If this reply fails, do NOT repeat the website request.
  await sendMessage(chatId, `(${label}) ${result.text}`, MENU);
}

function parseCommand(text) {
  const trimmed = text.trim();
  if (!trimmed.startsWith("/")) return null;

  const [first, ...args] = trimmed.split(/\s+/);

  return { name: first.slice(1).split("@")[0].toLowerCase(), args };
}

async function handleMessage(message) {
  if (
    message?.chat?.type !== "private" ||
    !message.from ||
    message.from.is_bot
  ) {
    return;
  }

  const chatId = message.chat.id;
  const userId = message.from.id;

  if (ALLOWED_USER_IDS.length > 0 && !ALLOWED_USER_IDS.includes(userId)) {
    return;
  }

  // Ignore stale commands after a connection outage.
  if (
    !Number.isFinite(message.date) ||
    Date.now() / 1000 - message.date > MAX_MESSAGE_AGE_SECONDS
  ) {
    return;
  }

  const text = typeof message.text === "string" ? message.text : "";
  const command = parseCommand(text);
  const now = Date.now();

  if (command?.name === "start") {
    pending.delete(userId);

    if (isAuthed(userId)) {
      await sendMessage(chatId, "You are authenticated. Use the toggle button below.", MENU);
    } else {
      await sendMessage(chatId, "Enter the secret password:", HIDE_MENU);
    }
    return;
  }

  if (command?.name === "admin") {
    await handleAdminLogin(message, command, now);
    return;
  }

  if (command?.name === "logout") {
    pending.delete(userId);

    const saved = mutate((d) => {
      d.admins = d.admins.filter((id) => id !== userId);
      d.users = d.users.filter((id) => id !== userId);
      delete d.modes[String(userId)];
      delete d.userTokens[String(userId)];
    });

    await sendMessage(
      chatId,
      saved
        ? "Logged out. Enter the secret password to authenticate again:"
        : "Could not save the logout. Check that the bot's folder is writable.",
      saved ? HIDE_MENU : MENU
    );
    return;
  }

  if (!isAuthed(userId)) {
    if (command) {
      await sendMessage(chatId, "Enter the secret password first:", HIDE_MENU);
    } else {
      await handleSecretPassword(message, text, now);
    }
    return;
  }

  let entry = pending.get(userId);

  if (entry && now - entry.startedAt > PENDING_TIMEOUT_MS) {
    pending.delete(userId);
    entry = undefined;
  }

  if (entry) {
    if (command?.name === "cancel") {
      pending.delete(userId);
      await sendMessage(chatId, "Cancelled.", MENU);
      return;
    }

    // A password may start with "/", so only /cancel interrupts that step.
    const knownCommand = command && KNOWN_COMMANDS.has(command.name);

    if (!knownCommand || entry.type === "add_password") {
      await handlePendingInput(message, text, entry, now);
      return;
    }

    pending.delete(userId);
  }

  if (!command) {
    if (text.trim().toLowerCase() === "toggle") {
      await handleToggle(chatId, userId, now);
    } else {
      await sendMessage(chatId, "Use the toggle button below.", MENU);
    }
    return;
  }

  switch (command.name) {
    case "help":
      await sendMessage(chatId, helpText(userId), MENU);
      return;

    case "cancel":
      await sendMessage(chatId, "Nothing to cancel.", MENU);
      return;

    case "switch": {
      if (data.modes[String(userId)] !== "token") {
        await sendMessage(chatId, "You are already using the website account.", MENU);
        return;
      }

      const saved = mutate((d) => {
        d.modes[String(userId)] = "account";
      });

      await sendMessage(
        chatId,
        saved
          ? "Switched back to the website account."
          : "Could not save the change. Check that the bot's folder is writable.",
        MENU
      );
      return;
    }

    case "token": {
      if (command.args.length > 0) {
        await deleteMessageQuietly(chatId, message.message_id);
        const token = parseUserToken(command.args.join(""));

        if (!token) {
          await sendMessage(
            chatId,
            "That does not look like a valid token. Send /token YOUR_TOKEN (only the token value).",
            MENU
          );
          return;
        }

        await saveUserToken(chatId, userId, token);
        return;
      }

      if (data.userTokens[String(userId)]) {
        const saved = mutate((d) => {
          d.modes[String(userId)] = "token";
        });

        await sendMessage(
          chatId,
          saved
            ? "Your token is used now. Send /switch to go back to the website account, or /token NEW_TOKEN to replace it."
            : "Could not save the change. Check that the bot's folder is writable.",
          MENU
        );
        return;
      }

      pending.set(userId, { type: "token", username: "", startedAt: now });

      await sendMessage(
        chatId,
        "Send your AuthorizationToken value (only the value). " +
          "The bot will try to delete your message. Send /cancel to abort."
      );
      return;
    }

    case "accounts":
      if (!isAdmin(userId)) break;
      await sendAccountsView(chatId);
      return;

    case "adminp": {
      if (!isAdmin(userId)) break;

      // The message contains passwords: remove it from the chat.
      await deleteMessageQuietly(chatId, message.message_id);

      if (command.args.length !== 2) {
        await sendMessage(
          chatId,
          "Usage: /adminp CURRENT_PASSWORD NEW_PASSWORD (passwords cannot contain spaces)."
        );
        return;
      }

      const [current, next] = command.args;
      const wait = lockSecondsLeft(adminAttempts, userId, now);

      if (wait) {
        await sendMessage(chatId, `Too many incorrect passwords. Try again in ${wait} seconds.`);
        return;
      }

      if (!adminPasswordMatches(current)) {
        const locked = registerFailure(adminAttempts, userId, now);

        await sendMessage(
          chatId,
          locked
            ? "Too many incorrect passwords. Locked for 5 minutes."
            : "The current admin password is incorrect."
        );
        return;
      }

      adminAttempts.delete(userId);

      if (next.length < 12 || next.length > 200) {
        await sendMessage(chatId, "The new admin password must be 12 to 200 characters.");
        return;
      }

      if (next === current) {
        await sendMessage(chatId, "The new password must differ from the current one.");
        return;
      }

      const saved = mutate((d) => {
        d.adminPasswordHash = hashAdminPassword(next);
      });

      await sendMessage(
        chatId,
        saved
          ? "The admin password was changed."
          : "Could not save the new password. Nothing was changed."
      );
      return;
    }

    default:
      break;
  }

  await sendMessage(chatId, "Unknown command. Send /help.", MENU);
}

function removeExpiredRecords() {
  const now = Date.now();

  for (const map of [passwordAttempts, adminAttempts]) {
    for (const [userId, record] of map) {
      if (now - record.updatedAt > LOCKOUT_DURATION_MS * 2) map.delete(userId);
    }
  }

  for (const [userId, entry] of pending) {
    if (now - entry.startedAt > PENDING_TIMEOUT_MS) pending.delete(userId);
  }
}

async function main() {
  initialize();

  const bot = await telegram("getMe");
  const webhook = await telegram("getWebhookInfo");

  if (webhook.url) {
    throw new Error(
      "This bot has an active webhook. Use a new dedicated bot token, " +
        "or deliberately remove the webhook in the application that owns it."
    );
  }

  // Skip commands queued before this process started.
  const pendingUpdates = await telegram("getUpdates", {
    offset: -1,
    limit: 1,
    timeout: 0,
    allowed_updates: ["message", "callback_query"],
  });

  let offset = pendingUpdates.length
    ? pendingUpdates[pendingUpdates.length - 1].update_id + 1
    : 0;

  console.log(`Bot @${bot.username} is running.`);
  console.log("Open its private chat and send /start.");
  console.log("Keep this terminal open. Press Ctrl+C to stop.");

  function stop() {
    stopping = true;
    console.log("Stopping after the current request finishes...");
  }

  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  while (!stopping) {
    try {
      const updates = await telegram(
        "getUpdates",
        {
          offset,
          timeout: 25,
          allowed_updates: ["message", "callback_query"],
        },
        35000
      );

      for (const update of updates) {
        if (stopping) break;
        if (update.update_id < offset) continue;

        // Advance before processing so a failed reply never repeats a toggle.
        offset = update.update_id + 1;

        try {
          if (update.message) {
            await handleMessage(update.message);
          } else if (update.callback_query) {
            await handleCallback(update.callback_query);
          }
        } catch {
          console.error(
            "Update handling or reply failed. " +
              "It will not be retried. " +
              "If you requested a toggle, check the website."
          );
        }
      }

      removeExpiredRecords();
    } catch (error) {
      if ([401, 404, 409].includes(error.code)) {
        throw new Error(
          `Telegram polling stopped: error ${error.code}. ` +
            "Check your bot token and make sure only one copy is running."
        );
      }

      console.error("Telegram connection unavailable. Reconnecting shortly...");

      const waitMs = Math.min(
        60000,
        Math.max(3000, (error.retryAfter || 0) * 1000)
      );

      await sleep(waitMs);
    }
  }
}

export { initialize, handleMessage, handleCallback, data };
export const testHooks = {
  resetCooldown() {
    lastToggleAt = 0;
  },
};

if (process.env.TOGGLE_BOT_TEST !== "1") {
  main().catch((error) => {
    // Never print request objects, passwords, or cookies.
    console.error(error.message);
    process.exitCode = 1;
  });
}
