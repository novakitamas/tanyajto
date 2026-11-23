import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { encodeSecret, revealSecret } from "./secret-codec.mjs";

// Usage: node encode-secret.mjs
// Type or paste a secret (it is not shown). The script prints the lines to
// paste into toggle-bot.mjs, for example:
//   const INITIAL_ADMIN_PASSWORD = revealSecret([ ... ]);

let muted = false;

const output = new Writable({
  write(chunk, encoding, callback) {
    if (!muted) process.stdout.write(chunk, encoding);
    callback();
  },
});

const rl = createInterface({
  input: process.stdin,
  output,
  terminal: Boolean(process.stdin.isTTY),
});

rl.question("Secret to encode (hidden): ", (answer) => {
  muted = false;
  rl.close();

  const secret = answer.replace(/\r?\n$/, "");

  if (!secret) {
    console.error("\nNo secret entered.");
    process.exitCode = 1;
    return;
  }

  const chunks = encodeSecret(secret);

  if (revealSecret(chunks) !== secret) {
    console.error("\nSelf-check failed. Nothing was printed.");
    process.exitCode = 1;
    return;
  }

  console.log("\nPaste this into toggle-bot.mjs:\n");
  console.log("const SECRET_NAME = revealSecret([");
  for (const chunk of chunks) console.log(`  ${JSON.stringify(chunk)},`);
  console.log("]);");
});

muted = true;
