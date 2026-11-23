import { createHash } from "node:crypto";

// Light obfuscation, NOT encryption. Anyone who has this file can decode the
// values. It only keeps secrets from being readable at a glance (or in one
// line) in the repository. Use encode-secret.mjs to create new values.

const SALT = "tanyajto-secret-v1";
const CHUNK_SIZE = 6;

function mask(index, length) {
  return createHash("sha256").update(`${SALT}:${index}`).digest().subarray(0, length);
}

function xor(bytes, index) {
  const key = mask(index, bytes.length);

  return Buffer.from(bytes.map((byte, i) => byte ^ key[i]));
}

export function encodeSecret(value) {
  const bytes = Buffer.from(String(value), "utf8");
  const chunks = [];

  for (let start = 0, index = 0; start < bytes.length; start += CHUNK_SIZE, index++) {
    const part = bytes.subarray(start, start + CHUNK_SIZE);
    chunks.push(xor(part, index).toString("base64"));
  }

  return chunks;
}

export function revealSecret(chunks) {
  return Buffer.concat(
    chunks.map((chunk, index) => xor(Buffer.from(chunk, "base64"), index))
  ).toString("utf8");
}
