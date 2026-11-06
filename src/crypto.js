// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// ChaCha20 + the FXServer "v3#resource-uri" key derivation.
//
// FXServer hands every connecting client a per-resource key blob ("uri"); resource
// files may be served encrypted with a key derived from it:
//
//   masterKey = xor( base64(uri)[19:len-8] , 0x69 )[:-2]
//   iv        = base64(uri)[len-8:]
//   fileKey   = HMAC-SHA256(masterKey, fileName)
//   plaintext = ChaCha20(fileKey, iv, ciphertext)
//
// Two ChaCha20 layouts exist in the wild: the original 64-bit counter / 64-bit
// nonce variant (used by the reference tooling) and RFC 7539's 32-bit counter /
// 96-bit nonce variant. We support both and let the caller pick by verification.
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';

import { parseKeyBlob } from './keyblob.js';

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function rotl(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

export class ChaCha20 {
  /**
   * @param {Buffer|Uint8Array} key 32 bytes
   * @param {Buffer|Uint8Array} nonce 8 bytes (original) or 12 bytes (RFC 7539)
   * @param {{nonceSize?: 8|12, counter?: number}} [options]
   */
  constructor(key, nonce, options = {}) {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
    const nonceBuf = Buffer.isBuffer(nonce) ? nonce : Buffer.from(nonce);
    const nonceSize = options.nonceSize ?? nonceBuf.length;

    if (keyBuf.length !== 32) {
      throw new Error(`ChaCha20 key must be 32 bytes, got ${keyBuf.length}`);
    }
    if (nonceSize !== 8 && nonceSize !== 12) {
      throw new Error(`ChaCha20 nonce must be 8 or 12 bytes, got ${nonceBuf.length}`);
    }
    if (nonceBuf.length < nonceSize) {
      throw new Error(`ChaCha20 nonce truncated (${nonceBuf.length} < ${nonceSize})`);
    }

    this.nonceSize = nonceSize;
    this.state = new Uint32Array(16);

    for (let i = 0; i < 4; i++) this.state[i] = SIGMA[i];
    for (let i = 0; i < 8; i++) this.state[4 + i] = keyBuf.readUInt32LE(i * 4);

    const counter = options.counter ?? 0;
    this.state[12] = counter >>> 0;
    this.state[13] = Math.floor(counter / 0x100000000) >>> 0;

    if (nonceSize === 8) {
      this.state[14] = nonceBuf.readUInt32LE(0);
      this.state[15] = nonceBuf.readUInt32LE(4);
    } else {
      // Counter occupies word 12 only; the nonce fills 13..15.
      this.state[13] = nonceBuf.readUInt32LE(0);
      this.state[14] = nonceBuf.readUInt32LE(4);
      this.state[15] = nonceBuf.readUInt32LE(8);
    }

    this.block = new Uint8Array(64);
    this.offset = 64; // force generation on first use
  }

  _generateBlock() {
    const state = this.state;
    const working = state.slice();

    for (let i = 0; i < 10; i++) {
      quarterRound(working, 0, 4, 8, 12);
      quarterRound(working, 1, 5, 9, 13);
      quarterRound(working, 2, 6, 10, 14);
      quarterRound(working, 3, 7, 11, 15);
      quarterRound(working, 0, 5, 10, 15);
      quarterRound(working, 1, 6, 11, 12);
      quarterRound(working, 2, 7, 8, 13);
      quarterRound(working, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++) {
      const value = (working[i] + state[i]) >>> 0;
      const out = i * 4;
      this.block[out] = value & 0xff;
      this.block[out + 1] = (value >>> 8) & 0xff;
      this.block[out + 2] = (value >>> 16) & 0xff;
      this.block[out + 3] = (value >>> 24) & 0xff;
    }

    // Advance the block counter (64-bit in both layouts; the 96-bit-nonce form
    // only ever uses the low word in practice).
    state[12] = (state[12] + 1) >>> 0;
    if (state[12] === 0) state[13] = (state[13] + 1) >>> 0;

    this.offset = 0;
  }

  /** XOR `data` with the keystream, continuing where the previous call stopped. */
  xor(data) {
    const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const output = Buffer.allocUnsafe(input.length);

    for (let i = 0; i < input.length; i++) {
      if (this.offset === 64) this._generateBlock();
      output[i] = input[i] ^ this.block[this.offset];
      this.offset += 1;
    }

    return output;
  }

  /** Convenience for one-shot use. */
  static xor(key, nonce, data, options = {}) {
    return new ChaCha20(key, nonce, options).xor(data);
  }
}

/* ------------------------------------------------------------- XChaCha20 */

/**
 * HChaCha20: the ChaCha20 permutation without the feed-forward addition, used to
 * derive a subkey from the first 16 bytes of an XChaCha20 nonce.
 */
export function hchacha20(key, nonce16) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
  const nonceBuf = Buffer.isBuffer(nonce16) ? nonce16 : Buffer.from(nonce16);

  if (keyBuf.length !== 32) throw new Error('HChaCha20 key must be 32 bytes');
  if (nonceBuf.length !== 16) throw new Error('HChaCha20 nonce must be 16 bytes');

  const state = new Uint32Array(16);
  for (let i = 0; i < 4; i++) state[i] = SIGMA[i];
  for (let i = 0; i < 8; i++) state[4 + i] = keyBuf.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) state[12 + i] = nonceBuf.readUInt32LE(i * 4);

  const working = state.slice();

  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const output = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) output.writeUInt32LE(working[i], i * 4);
  for (let i = 0; i < 4; i++) output.writeUInt32LE(working[12 + i], 16 + i * 4);
  return output;
}

/** XChaCha20: HChaCha20 subkey + ChaCha20 with a 96-bit nonce. */
export function createXChaCha20(key, nonce24, options = {}) {
  const nonceBuf = Buffer.isBuffer(nonce24) ? nonce24 : Buffer.from(nonce24);
  if (nonceBuf.length !== 24) throw new Error('XChaCha20 nonce must be 24 bytes');

  const subkey = hchacha20(key, nonceBuf.subarray(0, 16));
  const nonce12 = Buffer.concat([Buffer.alloc(4), nonceBuf.subarray(16)]);
  return new ChaCha20(subkey, nonce12, {
    nonceSize: 12,
    counter: options.counter ?? 0,
  });
}

/* ------------------------------------------------------- resource-key blob */

const URI_KEY_SKIP = 19; // opaque header bytes in the decoded blob
const URI_XOR = 0x69;
const URI_IV_LEN = 8;
const URI_TRAILING_KEY_BYTES = 2;

export const URI_PREFIX = 'v3#';

/**
 * Decode a resource key blob.
 *
 * Two shapes are accepted:
 *   "v3#<base64>"                    obfuscated raw key material (legacy layout)
 *   "ci://<resource>/v3#<base64>"    MessagePack [[profile, cipher, key, iv]]
 *
 * @returns {{version: number, format: string, key: Buffer, iv: Buffer,
 *            profile?: string, algorithm?: string, raw: Buffer}}
 */
export function parseResourceUri(uri) {
  const text = String(uri ?? '').trim();
  if (!text) throw new Error('empty resource uri');

  const hashIndex = text.indexOf('#');
  const head = hashIndex >= 0 ? text.slice(0, hashIndex) : text;
  const encoded = hashIndex >= 0 ? text.slice(hashIndex + 1) : text;

  const versionMatch = /\/v(\d+)$/.exec(head) ?? /^v(\d+)$/.exec(head);
  const version = versionMatch ? Number(versionMatch[1]) : 0;

  const raw = Buffer.from(encoded, 'base64');
  if (raw.length === 0) throw new Error('resource uri carries no data');

  // MessagePack form: [[profile, cipher, key, iv]]. The key field is stored with
  // the same single-byte XOR mask as the legacy layout, so undo it here and keep
  // the stored form around in case a server ever hands it over unmasked.
  const structured = parseKeyBlob(raw);
  if (structured) {
    const rawKey = structured.key;
    const key = Buffer.from(Array.from(rawKey, (byte) => byte ^ URI_XOR));
    return {
      version,
      format: 'msgpack',
      profile: structured.profile,
      algorithm: structured.algorithm,
      key,
      rawKey,
      keyVariants: [key, rawKey],
      iv: structured.iv,
      raw,
    };
  }

  if (raw.length < URI_KEY_SKIP + URI_IV_LEN + URI_TRAILING_KEY_BYTES + 1) {
    throw new Error(`resource uri too short (${raw.length} bytes decoded)`);
  }

  const body = raw.subarray(URI_KEY_SKIP);
  const iv = Buffer.from(body.subarray(body.length - URI_IV_LEN));

  const obfuscated = body.subarray(0, body.length - URI_IV_LEN);
  const unmasked = Buffer.allocUnsafe(obfuscated.length);
  for (let i = 0; i < obfuscated.length; i++) {
    unmasked[i] = obfuscated[i] ^ URI_XOR;
  }

  const key = Buffer.from(unmasked.subarray(0, unmasked.length - URI_TRAILING_KEY_BYTES));
  if (key.length < 16) {
    throw new Error(`resource uri key material too short (${key.length} bytes)`);
  }

  return { version, format: 'obfuscated', key, rawKey: key, keyVariants: [key], iv, raw };
}

/** Per-file key: HMAC-SHA256(masterKey, fileName). */
export function deriveFileKey(masterKey, fileName) {
  return crypto.createHmac('sha256', masterKey).update(String(fileName)).digest();
}

const NONCE_MODES = Object.freeze({
  'chacha20': 8,
  'chacha20-rfc7539': 12,
});

/**
 * Decrypt a buffer with a resource key.
 * @param {Buffer} masterKey
 * @param {Buffer} iv 8-byte nonce from the uri
 * @param {Buffer} data
 * @param {string} fileName name used for the per-file HMAC
 * @param {'chacha20'|'chacha20-rfc7539'} mode
 */
export function decryptBuffer(masterKey, iv, data, fileName, mode = 'chacha20') {
  const nonceSize = NONCE_MODES[mode];
  if (!nonceSize) throw new Error(`unknown cipher mode: ${mode}`);

  const key = deriveFileKey(masterKey, fileName);
  const nonce = nonceSize === 12 ? Buffer.concat([iv, Buffer.alloc(4)]) : iv;
  return ChaCha20.xor(key, nonce, data, { nonceSize });
}

/**
 * Streaming decrypt of a file; returns the SHA-1 of the produced plaintext so the
 * caller can check it against the hash the server advertised.
 */
export async function decryptFile(srcPath, dstPath, { masterKey, iv, fileName, mode = 'chacha20', chunkSize = 4 * 1024 * 1024 }) {
  const nonceSize = NONCE_MODES[mode];
  if (!nonceSize) throw new Error(`unknown cipher mode: ${mode}`);

  const key = deriveFileKey(masterKey, fileName);
  const nonce = nonceSize === 12 ? Buffer.concat([iv, Buffer.alloc(4)]) : iv;
  const cipher = new ChaCha20(key, nonce, { nonceSize });

  const hash = crypto.createHash('sha1');
  const source = await fsp.open(srcPath, 'r');
  const target = await fsp.open(dstPath, 'w');

  try {
    const buffer = Buffer.allocUnsafe(chunkSize);
    let position = 0;

    for (;;) {
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
      if (bytesRead <= 0) break;

      const plain = cipher.xor(buffer.subarray(0, bytesRead));
      hash.update(plain);
      await target.write(plain, 0, plain.length);
      position += bytesRead;
    }
  } finally {
    await source.close();
    await target.close();
  }

  return hash.digest('hex');
}

/* ------------------------------------------------------------------ helpers */

export const RPF2_MAGIC = Buffer.from('RPF2', 'latin1');

/** Cheap sniff: does this buffer/file start with the RPF2 magic? */
export function startsWithRpf2(buffer) {
  if (buffer.length < 4) return false;
  return buffer[0] === 0x52 && buffer[1] === 0x50 && buffer[2] === 0x46 && buffer[3] === 0x32;
}

export async function fileStartsWithRpf2(filePath) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(4);
    const { bytesRead } = await handle.read(buffer, 0, 4, 0);
    return bytesRead === 4 && startsWithRpf2(buffer);
  } finally {
    await handle.close();
  }
}

export function hexDump(buffer, limit = 16) {
  return Buffer.from(buffer.subarray(0, limit)).toString('hex').replace(/(..)/g, '$1 ').trim();
}
