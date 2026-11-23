import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

// ============================================================
// ENTER YOUR THREE VALUES HERE
// ============================================================

const BOT_TOKEN = "9026012194:AAEfT7ZGeCII_AIjdHM7iPqDVDq8dNPpe6o";

// Paste ONLY the cookie value, without "AuthorizationToken=".
const AUTHORIZATION_TOKEN = "lLZownzl3K3mpb10Km6n1uP2bpZ3COJ8XhU9OsktCs0FMYQ6B33UW.o2nNzoCRhGdnMX4uWIZQXeM.yBo64%2FFJqXe.36gr5vWUc9EgVfebu.KcMmCEJDxztpMa6DwhtLcei32TQGxOr1.Z3v0gRDI.RjKZBR%2F4dIu";

// Use a unique password of at least 12 characters.
const SECRET_PASSWORD = "1234567891011";

// ============================================================

// Optional: restrict access to specific numeric Telegram user IDs.
// Example: const ALLOWED_USER_IDS = [123456789];
// Leave empty to allow anyone who knows your secret password.
const ALLOWED_USER_IDS = [];

const TARGET_URL =
  "https://rak.dzsula.xyz/dashboard/personnel-manager/gateways?/toggle";

const PAGE_URL =
  "https://rak.dzsula.xyz/dashboard/personnel-manager/gateways";

const LOCKOUT_DURATION_MS = 5 * 60 * 1000;
const MAX_PASSWORD_ATTEMPTS = 5;
const TOGGLE_COOLDOWN_MS = 3000;
const MAX_MESSAGE_AGE_SECONDS = 60;

const MENU = {
  keyboard: [[{ text: "toggle" }]],
  resize_keyboard: true,
  is_persistent: true,
};

const HIDE_MENU = {
  remove_keyboard: true,
};

// Authenticated Telegram user IDs. These never expire.
const sessions = new Map();
const passwordAttempts = new Map();

let lastToggleAt = 0;
let stopping = false;

// Saved beside this script, regardless of the terminal's working folder.
const AUTH_FILE = new URL("./toggle-bot-auth.json", import.meta.url);
const AUTH_TEMP_FILE = new URL("./toggle-bot-auth.json.tmp", import.meta.url);

// Changing the password or bot token invalidates saved authentication.
function authenticationFingerprint() {
  return createHash("sha256")
    .update(JSON.stringify([BOT_TOKEN, SECRET_PASSWORD]))
    .digest("hex");
}

function loadAuthentication() {
  let stored;

  try {
    stored = JSON.parse(readFileSync(AUTH_FILE, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      return;
    }

    throw new Error(
      "Could not read toggle-bot-auth.json. " +
        "Fix or delete that file, then restart the bot."
    );
  }

  if (
    stored.version !== 1 ||
    stored.fingerprint !== authenticationFingerprint()
  ) {
    // Old credentials must not keep users authenticated.
    return;
  }

  if (
    !Array.isArray(stored.userIds) ||
    !stored.userIds.every((id) => Number.isSafeInteger(id) && id > 0)
  ) {
    throw new Error(
      "Invalid authentication file. Delete toggle-bot-auth.json " +
        "and restart to require everyone to authenticate again."
    );
  }

  for (const userId of stored.userIds) {
    sessions.set(userId, true);
  }
}

function saveAuthentication() {
  const stored = {
    version: 1,
    fingerprint: authenticationFingerprint(),
    userIds: [...sessions.keys()],
  };

  // Write a temporary file first to avoid partial JSON writes.
  writeFileSync(AUTH_TEMP_FILE, JSON.stringify(stored, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });

  renameSync(AUTH_TEMP_FILE, AUTH_FILE);
}

function validateConfiguration() {
  if (Number(process.versions.node.split(".")[0]) < 22) {
    throw new Error("Please install Node.js 22 or newer.");
  }

  const values = {
    BOT_TOKEN,
    AUTHORIZATION_TOKEN,
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

  if (
    AUTHORIZATION_TOKEN.startsWith("AuthorizationToken=") ||
    /[;\r\n]/.test(AUTHORIZATION_TOKEN)
  ) {
    throw new Error("AUTHORIZATION_TOKEN must contain only the cookie value.");
  }

  if (SECRET_PASSWORD.length < 12) {
    throw new Error("SECRET_PASSWORD must be at least 12 characters.");
  }

  if (!ALLOWED_USER_IDS.every((id) => Number.isSafeInteger(id) && id > 0)) {
    throw new Error("ALLOWED_USER_IDS must contain numeric user IDs.");
  }
}

function passwordMatches(input) {
  const hash = (value) => createHash("sha256").update(value, "utf8").digest();

  return timingSafeEqual(hash(input), hash(SECRET_PASSWORD));
}

async function telegram(method, payload = {}, timeoutMs = 15000) {
  const response = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
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

async function deletePasswordMessage(chatId, messageId) {
  try {
    await telegram("deleteMessage", {
      chat_id: chatId,
      message_id: messageId,
    });
  } catch {
    // Best effort only. Never log or echo passwords.
  }
}

async function sendToggleRequest() {
  // Never automatically retry a toggle:
  // a second request could undo the first one.
  try {
    const response = await fetch(TARGET_URL, {
      method: "POST",
      headers: {
        Accept: "application/json, */*;q=0.9",
        "x-sveltekit-action": "true",
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: `AuthorizationToken=${AUTHORIZATION_TOKEN}`,
        Origin: new URL(PAGE_URL).origin,
        Referer: PAGE_URL,
      },

      // Empty form submission: no unknown fields are invented.
      body: new URLSearchParams(),

      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    const responseText = await response.text();

    const checkBeforeRetry =
      " Check the website before trying again. No automatic retry was made.";

    if (response.status >= 300 && response.status < 400) {
      return (
        `Server returned HTTP ${response.status} redirect. ` +
        "Your authorization cookie may have expired." +
        checkBeforeRetry
      );
    }

    if (!response.ok) {
      const authorizationHint =
        response.status === 401 || response.status === 403
          ? " Check your authorization cookie and permissions."
          : "";

      return (
        `Server returned HTTP ${response.status}.` +
        authorizationHint +
        checkBeforeRetry
      );
    }

    if (response.status === 204 || !responseText.trim()) {
      return (
        `Request accepted: HTTP ${response.status}. ` +
        "No resulting state was returned. Check the website."
      );
    }

    let result;

    try {
      result = JSON.parse(responseText);
    } catch {
      return (
        `Received HTTP ${response.status}, but not JSON. ` +
        "The toggle outcome is unconfirmed." +
        checkBeforeRetry
      );
    }

    if (result?.type === "failure" || result?.type === "error") {
      return (
        `The server action reported ${result.type} ` +
        `(status ${Number(result.status) || response.status}).` +
        checkBeforeRetry
      );
    }

    if (result?.type === "redirect") {
      return (
        "The server action returned a redirect. " +
        "The toggle outcome is unconfirmed." +
        checkBeforeRetry
      );
    }

    if (result?.type === "success") {
      return (
        "The server reported action success. " +
        "Check the website for the resulting state."
      );
    }

    return (
      `Received JSON: HTTP ${response.status}. ` +
      "Check the website for the resulting state."
    );
  } catch {
    return (
      "The request timed out or a network error occurred. " +
      "It may already have toggled. Check the website before " +
      "trying again. No automatic retry was made."
    );
  }
}

async function handleMessage(message) {
  // Only allow private conversations with human users.
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
  const command = text.trim();
  const now = Date.now();

  if (command === "/logout") {
    const wasAuthenticated = sessions.has(userId);
    sessions.delete(userId);

    try {
      saveAuthentication();
    } catch {
      // Restore the previous state if logout could not be persisted.
      if (wasAuthenticated) {
        sessions.set(userId, true);
      }

      await sendMessage(
        chatId,
        "Could not save logout. Your authentication was not changed. " +
          "Check that the bot's folder is writable.",
        wasAuthenticated ? MENU : HIDE_MENU
      );
      return;
    }

    await sendMessage(
      chatId,
      "Logged out. Enter the secret password to authenticate again:"
    );
    return;
  }

  if (command === "/start") {
    if (sessions.has(userId)) {
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

  if (!sessions.has(userId)) {
    let attempts = passwordAttempts.get(userId) || {
      failures: 0,
      lockedUntil: 0,
      updatedAt: now,
    };

    if (attempts.lockedUntil > now) {
      const secondsRemaining = Math.ceil((attempts.lockedUntil - now) / 1000);

      await sendMessage(
        chatId,
        `Too many incorrect passwords. Try again in ${secondsRemaining} seconds.`
      );

      return;
    }

    // Start fresh after an expired lockout.
    if (attempts.lockedUntil !== 0) {
      attempts = {
        failures: 0,
        lockedUntil: 0,
        updatedAt: now,
      };
    }

    if (!text) {
      await sendMessage(chatId, "Enter the secret password as a text message:");
      return;
    }

    await deletePasswordMessage(chatId, message.message_id);

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
    sessions.set(userId, true);

    try {
      saveAuthentication();
    } catch {
      sessions.delete(userId);

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

  const result = await sendToggleRequest();

  // If this reply fails, do NOT repeat the website request.
  await sendMessage(chatId, result, MENU);
}

function removeExpiredRecords() {
  const now = Date.now();

  // Only clean up password-attempt records.
  // Authenticated users do not expire.
  for (const [userId, attempts] of passwordAttempts) {
    if (now - attempts.updatedAt > LOCKOUT_DURATION_MS * 2) {
      passwordAttempts.delete(userId);
    }
  }
}

async function main() {
  validateConfiguration();
  loadAuthentication();

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
    allowed_updates: ["message"],
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
          allowed_updates: ["message"],
        },
        35000
      );

      for (const update of updates) {
        if (stopping) break;
        if (update.update_id < offset) continue;

        // Advance before processing to prevent reprocessing if
        // a Telegram reply fails after a successful toggle.
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

main().catch((error) => {
  // Avoid printing request objects, tokens, or cookies.
  console.error(error.message);
  process.exitCode = 1;
});