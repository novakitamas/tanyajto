import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

// ============================================================
// ENTER YOUR VALUES HERE
// ============================================================

const BOT_TOKEN = "9026012194:AAEfT7ZGeCII_AIjdHM7iPqDVDq8dNPpe6o"; // from @BotFather

// Your login for https://rak.dzsula.xyz/dashboard/login
const SITE_USERNAME = "Tams";
const SITE_PASSWORD = "FB&EXP8xIw$HIn^Y";

// Password people must type in Telegram before they get the toggle menu.
const SECRET_PASSWORD = "UltraSecurePassword123!"; // 12+ characters

// ============================================================

// Optional: restrict the bot to specific numeric Telegram user IDs.
// Example: const ALLOWED_USER_IDS = [123456789];
const ALLOWED_USER_IDS = [];

// Daily schedule (24-hour clock, in the timezone below).
const TIMEZONE = "Europe/Budapest";
const DAILY_LOGIN_TIME = "04:00";
const RETRY_LOGIN_TIME = "06:00";

const SITE_ORIGIN = "https://rak.dzsula.xyz";
const LOGIN_PAGE_URL = `${SITE_ORIGIN}/dashboard/login`;
const LOGIN_URL = `${SITE_ORIGIN}/dashboard/login?/login`;
const TOGGLE_PAGE_URL = `${SITE_ORIGIN}/dashboard/personnel-manager/gateways`;
const TOGGLE_URL = `${TOGGLE_PAGE_URL}?/toggle`;

const COOKIE_NAME = "AuthorizationToken";
const DEFAULT_TOKEN_LIFETIME_MS = 4 * 60 * 60 * 1000;
const EXPIRY_MARGIN_MS = 60 * 1000;
const ON_DEMAND_RETRY_DELAY_MS = 60 * 1000;
const ON_DEMAND_BAD_PASSWORD_DELAY_MS = 60 * 60 * 1000;
const SCHEDULER_TICK_MS = 30 * 1000;
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

// Telegram users who entered SECRET_PASSWORD. This never expires.
const authenticatedUsers = new Set();
const passwordAttempts = new Map();

// Website token and schedule bookkeeping (saved to disk).
const state = {
  cookie: "",
  expiresAt: 0,
  lastPrimaryDate: "",
  lastSuccessDate: "",
  lastRetryDate: "",
};

let lastToggleAt = 0;
let stopping = false;
let refreshInProgress = null;
let onDemandBlockedUntil = 0;

// In Docker, AUTH_DIR=/data (a persistent volume). Otherwise the script's folder.
const AUTH_DIR =
  process.env.AUTH_DIR || fileURLToPath(new URL(".", import.meta.url));
const STATE_FILE = join(AUTH_DIR, "toggle-bot-state.json");
const STATE_TEMP_FILE = join(AUTH_DIR, "toggle-bot-state.json.tmp");

// Changing any of these values invalidates the saved state.
function fingerprint() {
  return createHash("sha256")
    .update(JSON.stringify([BOT_TOKEN, SECRET_PASSWORD, SITE_USERNAME]))
    .digest("hex");
}

function isValidCookieValue(value) {
  return /^[A-Za-z0-9%._~+\/=-]+$/.test(value);
}

function loadState() {
  let stored;

  try {
    stored = JSON.parse(readFileSync(STATE_FILE, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return;

    throw new Error(
      "Could not read toggle-bot-state.json. " +
        "Fix or delete that file, then restart the bot."
    );
  }

  if (stored.version !== 3 || stored.fingerprint !== fingerprint()) return;

  if (Array.isArray(stored.users)) {
    for (const id of stored.users) {
      if (Number.isSafeInteger(id) && id > 0) authenticatedUsers.add(id);
    }
  }

  if (
    typeof stored.cookie === "string" &&
    isValidCookieValue(stored.cookie) &&
    Number.isFinite(stored.expiresAt)
  ) {
    state.cookie = stored.cookie;
    state.expiresAt = stored.expiresAt;
  }

  for (const key of ["lastPrimaryDate", "lastSuccessDate", "lastRetryDate"]) {
    if (typeof stored[key] === "string") state[key] = stored[key];
  }
}

function saveState() {
  const stored = {
    version: 3,
    fingerprint: fingerprint(),
    users: [...authenticatedUsers],
    ...state,
  };

  writeFileSync(STATE_TEMP_FILE, JSON.stringify(stored, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });

  renameSync(STATE_TEMP_FILE, STATE_FILE);
}

function trySaveState() {
  try {
    saveState();
    return true;
  } catch {
    return false;
  }
}

function parseClock(value, name) {
  const match = /^(\d{1,2}):(\d{2})$/.exec(value);

  if (!match || Number(match[1]) > 23 || Number(match[2]) > 59) {
    throw new Error(`${name} must look like "04:00".`);
  }

  return Number(match[1]) * 60 + Number(match[2]);
}

const DAILY_MINUTES = parseClock(DAILY_LOGIN_TIME, "DAILY_LOGIN_TIME");
const RETRY_MINUTES = parseClock(RETRY_LOGIN_TIME, "RETRY_LOGIN_TIME");

function validateConfiguration() {
  if (Number(process.versions.node.split(".")[0]) < 22) {
    throw new Error("Please install Node.js 22 or newer.");
  }

  const values = {
    BOT_TOKEN,
    SITE_USERNAME,
    SITE_PASSWORD,
    SECRET_PASSWORD,
  };

  for (const [name, value] of Object.entries(values)) {
    if (!value || value.startsWith("PASTE_")) {
      throw new Error(`Fill in ${name} at the top of the script.`);
    }
  }

  if (!/^\d+:[A-Za-z0-9_-]+$/.test(BOT_TOKEN)) {
    throw new Error("BOT_TOKEN has an invalid format.");
  }

  if (SECRET_PASSWORD.length < 12) {
    throw new Error("SECRET_PASSWORD must be at least 12 characters.");
  }

  if (!ALLOWED_USER_IDS.every((id) => Number.isSafeInteger(id) && id > 0)) {
    throw new Error("ALLOWED_USER_IDS must contain numeric user IDs.");
  }

  if (RETRY_MINUTES <= DAILY_MINUTES) {
    throw new Error("RETRY_LOGIN_TIME must be later than DAILY_LOGIN_TIME.");
  }

  try {
    new Intl.DateTimeFormat("en-CA", { timeZone: TIMEZONE });
  } catch {
    throw new Error(`TIMEZONE "${TIMEZONE}" is not a valid timezone name.`);
  }
}

function passwordMatches(input) {
  const hash = (value) => createHash("sha256").update(value, "utf8").digest();

  return timingSafeEqual(hash(input), hash(SECRET_PASSWORD));
}

// Current date (YYYY-MM-DD) and minutes since midnight in TIMEZONE.
function localNow() {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone: TIMEZONE,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    })
      .formatToParts(new Date())
      .map((part) => [part.type, part.value])
  );

  return {
    date: `${parts.year}-${parts.month}-${parts.day}`,
    minutes: Number(parts.hour) * 60 + Number(parts.minute),
  };
}

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString("hu-HU", {
    timeZone: TIMEZONE,
    hour: "2-digit",
    minute: "2-digit",
  });
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

function sendMessage(chatId, text, keyboard = HIDE_MENU) {
  return telegram("sendMessage", {
    chat_id: chatId,
    text,
    reply_markup: keyboard,
  });
}

async function deleteMessageQuietly(chatId, messageId) {
  try {
    await telegram("deleteMessage", {
      chat_id: chatId,
      message_id: messageId,
    });
  } catch {
    // Best effort only. Never log or echo passwords.
  }
}

// In private chats the chat ID equals the user ID.
async function notifyUsers(text) {
  for (const userId of authenticatedUsers) {
    try {
      await sendMessage(userId, text, MENU);
    } catch {
      // Ignore users who blocked the bot.
    }
  }
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

// One login attempt. Never includes the password in any message.
async function loginToSite() {
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
      body: new URLSearchParams({
        redirectTo: "",
        username: SITE_USERNAME,
        password: SITE_PASSWORD,
      }),
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    const text = await response.text();

    let result = null;
    try {
      result = JSON.parse(text);
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

// Logs in and stores the new token. Only one login runs at a time.
function refreshToken(reason) {
  if (refreshInProgress) return refreshInProgress;

  refreshInProgress = (async () => {
    const result = await loginToSite();

    if (result.ok) {
      state.cookie = result.cookie.value;
      state.expiresAt = result.cookie.expiresAt;
      trySaveState();

      console.log(
        `[${new Date().toISOString()}] Token refreshed (${reason}). ` +
          `Valid until ${formatTime(state.expiresAt)}.`
      );
    } else {
      console.error(
        `[${new Date().toISOString()}] Token refresh failed (${reason}): ` +
          result.message
      );
    }

    return result;
  })().finally(() => {
    refreshInProgress = null;
  });

  return refreshInProgress;
}

// Used before a toggle: logs in only if there is no valid token.
async function ensureToken() {
  if (state.cookie && state.expiresAt > Date.now() + 30 * 1000) {
    return { ok: true };
  }

  if (onDemandBlockedUntil > Date.now()) {
    const seconds = Math.ceil((onDemandBlockedUntil - Date.now()) / 1000);

    return {
      ok: false,
      message:
        "The token has expired and the last login attempt failed. " +
        `Next automatic attempt in about ${seconds} seconds.`,
    };
  }

  const result = await refreshToken("on demand");

  if (!result.ok) {
    onDemandBlockedUntil =
      Date.now() +
      (result.wrongCredentials
        ? ON_DEMAND_BAD_PASSWORD_DELAY_MS
        : ON_DEMAND_RETRY_DELAY_MS);

    return {
      ok: false,
      message: `Could not log in to the website. ${result.message}`,
    };
  }

  onDemandBlockedUntil = 0;
  return { ok: true };
}

// Runs every 30 seconds: 04:00 login, then 06:00 retry if 04:00 failed.
async function runScheduler() {
  const now = localNow();

  if (now.minutes >= DAILY_MINUTES && state.lastPrimaryDate !== now.date) {
    state.lastPrimaryDate = now.date;
    trySaveState();

    const result = await refreshToken(`scheduled ${DAILY_LOGIN_TIME}`);

    if (result.ok) {
      state.lastSuccessDate = now.date;
      onDemandBlockedUntil = 0;
      trySaveState();
    }

    return;
  }

  if (
    now.minutes >= RETRY_MINUTES &&
    state.lastPrimaryDate === now.date &&
    state.lastSuccessDate !== now.date &&
    state.lastRetryDate !== now.date
  ) {
    state.lastRetryDate = now.date;
    trySaveState();

    const result = await refreshToken(`retry ${RETRY_LOGIN_TIME}`);

    if (result.ok) {
      state.lastSuccessDate = now.date;
      onDemandBlockedUntil = 0;
      trySaveState();
    } else {
      await notifyUsers(
        `Automatic login failed at ${DAILY_LOGIN_TIME} and again at ` +
          `${RETRY_LOGIN_TIME}. ${result.message} ` +
          "The bot will try to log in when you press toggle."
      );
    }
  }
}

// Returns { text, sessionInvalid }. A toggle is never retried automatically.
async function sendToggleRequest(cookie) {
  const checkBeforeRetry =
    " Check the website before trying again. No automatic retry was made.";

  try {
    const response = await fetch(TOGGLE_URL, {
      method: "POST",
      headers: {
        Accept: "application/json, */*;q=0.9",
        "x-sveltekit-action": "true",
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: `${COOKIE_NAME}=${cookie}`,
        Origin: SITE_ORIGIN,
        Referer: TOGGLE_PAGE_URL,
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

  if (
    !Number.isFinite(message.date) ||
    Date.now() / 1000 - message.date > MAX_MESSAGE_AGE_SECONDS
  ) {
    return;
  }

  const text = typeof message.text === "string" ? message.text : "";
  const command = text.trim();
  const now = Date.now();

  if (command === "/logout") {
    authenticatedUsers.delete(userId);
    const saved = trySaveState();

    await sendMessage(
      chatId,
      "Logged out. Enter the secret password to authenticate again:" +
        (saved ? "" : " (Warning: the logout could not be saved to disk.)")
    );
    return;
  }

  if (command === "/start") {
    if (authenticatedUsers.has(userId)) {
      await sendMessage(
        chatId,
        "You are authenticated. Use the toggle button below.",
        MENU
      );
    } else {
      await sendMessage(chatId, "Enter the secret password:");
    }

    return;
  }

  if (!authenticatedUsers.has(userId)) {
    let attempts = passwordAttempts.get(userId) || {
      failures: 0,
      lockedUntil: 0,
      updatedAt: now,
    };

    if (attempts.lockedUntil > now) {
      const seconds = Math.ceil((attempts.lockedUntil - now) / 1000);

      await sendMessage(
        chatId,
        `Too many incorrect passwords. Try again in ${seconds} seconds.`
      );
      return;
    }

    if (attempts.lockedUntil !== 0) {
      attempts = { failures: 0, lockedUntil: 0, updatedAt: now };
    }

    if (!text) {
      await sendMessage(chatId, "Enter the secret password as a text message:");
      return;
    }

    await deleteMessageQuietly(chatId, message.message_id);

    if (!passwordMatches(text)) {
      attempts.failures += 1;
      attempts.updatedAt = now;

      if (attempts.failures >= MAX_PASSWORD_ATTEMPTS) {
        attempts.lockedUntil = now + LOCKOUT_DURATION_MS;
      }

      passwordAttempts.set(userId, attempts);

      await sendMessage(
        chatId,
        attempts.lockedUntil > now
          ? "Too many incorrect passwords. Locked for 5 minutes."
          : "Incorrect password. Try again:"
      );
      return;
    }

    passwordAttempts.delete(userId);
    authenticatedUsers.add(userId);

    if (!trySaveState()) {
      authenticatedUsers.delete(userId);

      await sendMessage(
        chatId,
        "The password was correct, but authentication could not be saved. " +
          "Check that the bot's folder is writable, then try again."
      );
      return;
    }

    await sendMessage(
      chatId,
      "Authenticated. Your login does not expire. Use toggle below.",
      MENU
    );
    return;
  }

  if (command.toLowerCase() !== "toggle") {
    await sendMessage(chatId, "Use the toggle button below.", MENU);
    return;
  }

  if (now - lastToggleAt < TOGGLE_COOLDOWN_MS) {
    await sendMessage(
      chatId,
      "Please wait a few seconds before another toggle.",
      MENU
    );
    return;
  }

  lastToggleAt = now;

  const token = await ensureToken();

  if (!token.ok) {
    await sendMessage(chatId, `${token.message} The toggle was not performed.`, MENU);
    return;
  }

  const result = await sendToggleRequest(state.cookie);

  if (result.sessionInvalid) {
    // The cookie was rejected before anything happened. Get a fresh one,
    // but let the user decide to press toggle again.
    state.cookie = "";
    state.expiresAt = 0;
    trySaveState();

    const refreshed = await refreshToken("rejected token");

    await sendMessage(
      chatId,
      refreshed.ok
        ? `${result.text} A new token was fetched. Press toggle again.`
        : `${result.text} ${refreshed.message}`,
      MENU
    );
    return;
  }

  // If this reply fails, do NOT repeat the website request.
  await sendMessage(chatId, result.text, MENU);
}

function removeOldRecords() {
  const now = Date.now();

  for (const [userId, attempts] of passwordAttempts) {
    if (now - attempts.updatedAt > LOCKOUT_DURATION_MS * 2) {
      passwordAttempts.delete(userId);
    }
  }
}

async function main() {
  validateConfiguration();
  loadState();

  const bot = await telegram("getMe");
  const webhook = await telegram("getWebhookInfo");

  if (webhook.url) {
    throw new Error(
      "This bot has an active webhook. Use a new dedicated bot token, " +
        "or deliberately remove the webhook in the application that owns it."
    );
  }

  const pendingUpdates = await telegram("getUpdates", {
    offset: -1,
    limit: 1,
    timeout: 0,
    allowed_updates: ["message"],
  });

  let offset = pendingUpdates.length
    ? pendingUpdates[pendingUpdates.length - 1].update_id + 1
    : 0;

  console.log(`Bot @${bot.username} is running.`);
  console.log(
    `Daily website login at ${DAILY_LOGIN_TIME}, retry at ` +
      `${RETRY_LOGIN_TIME} (${TIMEZONE}).`
  );
  console.log("Open the bot's private chat and send /start. Ctrl+C stops it.");

  let schedulerRunning = false;

  const schedulerTimer = setInterval(() => {
    if (schedulerRunning || stopping) return;
    schedulerRunning = true;

    runScheduler()
      .catch(() => console.error("Scheduler error."))
      .finally(() => {
        schedulerRunning = false;
      });
  }, SCHEDULER_TICK_MS);

  function stop() {
    stopping = true;
    clearInterval(schedulerTimer);
    console.log("Stopping after the current request finishes...");
  }

  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  while (!stopping) {
    try {
      const updates = await telegram(
        "getUpdates",
        { offset, timeout: 25, allowed_updates: ["message"] },
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
          }
        } catch {
          console.error(
            "Message handling or reply failed. " +
              "This message will not be retried. " +
              "If you requested a toggle, check the website."
          );
        }
      }

      removeOldRecords();
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

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});