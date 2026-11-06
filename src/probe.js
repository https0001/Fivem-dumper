// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Profile discovery for resource payloads whose encryption scheme is not the one
// documented in the README.
//
// FXServer itself hands clients a plain RPF2. Servers running a resource-protection
// layer instead hand out an encrypted blob plus a "v3#..." key blob, and the exact
// key derivation / cipher differs between products. Rather than hard-code one guess,
// this module probes a bounded matrix of plausible combinations against the first
// bytes of the payload and reports every combination that yields a valid RPF2 magic.
//
// The probe is cheap (a few hundred bytes per candidate), so it can run before any
// expensive full-file decryption.
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';

import { ChaCha20, createXChaCha20 } from './crypto.js';

const zeros = (n) => Buffer.alloc(n);
const RPF2 = Buffer.from('RPF2', 'latin1');

/* ------------------------------------------------------------ key sources */

const KEY_SOURCES = [
  {
    id: 'hmac(name)',
    derive: (masterKey, fileName) =>
      crypto.createHmac('sha256', masterKey).update(String(fileName)).digest(),
  },
  {
    id: 'hmac("resource.rpf")',
    derive: (masterKey) =>
      crypto.createHmac('sha256', masterKey).update('resource.rpf').digest(),
  },
  {
    id: 'raw-key',
    derive: (masterKey) => (masterKey.length === 32 ? masterKey : null),
  },
  {
    id: 'sha256(key||name)',
    derive: (masterKey, fileName) =>
      crypto.createHash('sha256').update(masterKey).update(String(fileName)).digest(),
  },
];

/* ---------------------------------------------------------- cipher layouts */

const CIPHERS = [
  // Original ChaCha20, 64-bit counter + 64-bit nonce.
  { id: 'chacha20/iv8/c0', kind: 'chacha', nonceSize: 8, counter: 0, makeNonce: (iv) => iv },
  { id: 'chacha20/iv8/c1', kind: 'chacha', nonceSize: 8, counter: 1, makeNonce: (iv) => iv },
  // RFC 7539, 96-bit nonce built from the 8-byte iv either padded at the end...
  {
    id: 'chacha20/iv8+0^4/c0',
    kind: 'chacha',
    nonceSize: 12,
    counter: 0,
    makeNonce: (iv) => Buffer.concat([iv, zeros(4)]),
  },
  {
    id: 'chacha20/iv8+0^4/c1',
    kind: 'chacha',
    nonceSize: 12,
    counter: 1,
    makeNonce: (iv) => Buffer.concat([iv, zeros(4)]),
  },
  // ...or padded at the front.
  {
    id: 'chacha20/0^4+iv8/c0',
    kind: 'chacha',
    nonceSize: 12,
    counter: 0,
    makeNonce: (iv) => Buffer.concat([zeros(4), iv]),
  },
  {
    id: 'chacha20/0^4+iv8/c1',
    kind: 'chacha',
    nonceSize: 12,
    counter: 1,
    makeNonce: (iv) => Buffer.concat([zeros(4), iv]),
  },
  // XChaCha20 (24-byte nonce).
  {
    id: 'xchacha20/iv8+0^16/c0',
    kind: 'xchacha',
    counter: 0,
    makeNonce: (iv) => Buffer.concat([iv, zeros(16)]),
  },
  {
    id: 'xchacha20/iv8+0^16/c1',
    kind: 'xchacha',
    counter: 1,
    makeNonce: (iv) => Buffer.concat([iv, zeros(16)]),
  },
  // AES-256-CTR with a 16-byte IV built from the 8-byte iv.
  {
    id: 'aes256ctr/iv8+0^8',
    kind: 'aes-ctr',
    makeNonce: (iv) => Buffer.concat([iv, zeros(8)]),
  },
  {
    id: 'aes256ctr/0^8+iv8',
    kind: 'aes-ctr',
    makeNonce: (iv) => Buffer.concat([zeros(8), iv]),
  },
];

/** Instantiate a stateful keystream for one candidate. */
export function createStreamFor(spec, key, iv) {
  switch (spec.kind) {
    case 'chacha':
      return new ChaCha20(key, spec.makeNonce(iv), {
        nonceSize: spec.nonceSize,
        counter: spec.counter,
      });
    case 'xchacha':
      return createXChaCha20(key, spec.makeNonce(iv), { counter: spec.counter });
    case 'aes-ctr': {
      const cipher = crypto.createCipheriv('aes-256-ctr', key, spec.makeNonce(iv));
      return { xor: (buffer) => cipher.update(buffer) };
    }
    default:
      throw new Error(`unknown cipher spec: ${spec.kind}`);
  }
}

/** True when the buffer begins with the RPF2 packfile magic. */
export function looksLikeRpf2(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 4 && buffer.subarray(0, 4).equals(RPF2);
}

/** Friendly names for the combinations people actually hit. */
const HIT_LABELS = {
  'hmac(name) + chacha20/iv8/c0': 'chacha20 (standard)',
  'hmac(name) + chacha20/iv8+0^4/c0': 'chacha20 (rfc7539 nonce)',
};

/**
 * Try every key source x cipher layout against `head`.
 * @returns {{hits: object[], results: object[]}}
 */
export function probeDecryption({ head, keyMaterial, fileName }) {
  const hits = [];
  const results = [];

  const masterKeys =
    Array.isArray(keyMaterial.keyVariants) && keyMaterial.keyVariants.length > 0
      ? keyMaterial.keyVariants
      : [keyMaterial.key];

  for (const masterKey of masterKeys) {
    for (const source of KEY_SOURCES) {
      let key;
      try {
        key = source.derive(masterKey, fileName);
      } catch {
        key = null;
      }
      if (!key || key.length !== 32) continue;

      for (const spec of CIPHERS) {
        const id = `${source.id} + ${spec.id}`;
        let output;
        try {
          output = createStreamFor(spec, key, keyMaterial.iv).xor(head);
        } catch (error) {
          results.push({ id, error: error.message });
          continue;
        }

        const match = looksLikeRpf2(output);
        results.push({
          id,
          match,
          first8: output.subarray(0, 8).toString('hex'),
        });

        if (match) {
          hits.push({
            id,
            label: HIT_LABELS[id] ?? id,
            keySource: source.id,
            cipher: spec.id,
            // Everything needed to reproduce the keystream over the full file.
            spec,
            key,
            iv: keyMaterial.iv,
          });
        }
      }
    }
  }

  return { hits, results };
}

/**
 * Decrypt a whole file with a probe hit. Returns the SHA-1 of the plaintext so the
 * caller can verify it against the advertised hash.
 */
export async function decryptFileWithProfile(srcPath, dstPath, hit, chunkSize = 4 * 1024 * 1024) {  const stream = createStreamFor(hit.spec, hit.key, hit.iv);
  const hash = crypto.createHash('sha1');
  const source = await fsp.open(srcPath, 'r');
  const target = await fsp.open(dstPath, 'w');

  try {
    const buffer = Buffer.allocUnsafe(chunkSize);
    let position = 0;

    for (;;) {
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
      if (bytesRead <= 0) break;

      const plain = stream.xor(buffer.subarray(0, bytesRead));
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

/* --------------------------------------------------------- brute forcing */

// The few layouts worth spending brute-force time on.
const BRUTE_CIPHERS = CIPHERS.filter((spec) =>
  [
    'chacha20/iv8/c0',
    'chacha20/iv8/c1',
    'chacha20/iv8+0^4/c0',
    'xchacha20/iv8+0^16/c0',
    'aes256ctr/iv8+0^8',
  ].includes(spec.id),
);

/**
 * Some protection layers keep the "v3#" blob shape but shuffle its parameters:
 * a different header length, a different obfuscation byte, a different amount of
 * trailing padding. This searches that (bounded) space for a key that produces an
 * RPF2 header. The 8-byte iv is assumed to be the tail of the decoded blob, which
 * holds for every sample seen so far.
 *
 * Cost: ~19k key candidates x 5 layouts, one ChaCha block each — a couple of
 * seconds. Only worth running for a payload we could not otherwise open.
 */
export function bruteForceKeyDecode({ head, uri, maxSkip = 24, maxHits = 4 }) {
  const text = String(uri ?? '');
  const match = /^v(\d+)#(.*)$/s.exec(text);
  const raw = Buffer.from(match ? match[2] : text, 'base64');
  const hits = [];
  const sample = head.subarray(0, 64);

  for (let skip = 0; skip <= maxSkip; skip++) {    if (raw.length - skip < 41) continue; // 32-byte key + 8-byte iv + slack

    const body = raw.subarray(skip);
    const iv = body.subarray(body.length - 8);
    const masked = body.subarray(0, body.length - 8);
    const unmasked = Buffer.allocUnsafe(masked.length);

    for (let xorByte = 0; xorByte < 256; xorByte++) {
      for (let i = 0; i < masked.length; i++) unmasked[i] = masked[i] ^ xorByte;

      for (let trim = 0; trim <= 2; trim++) {
        const keyRaw = unmasked.subarray(0, unmasked.length - trim);
        if (keyRaw.length < 32) continue;

        const key = keyRaw.subarray(0, 32);

        for (const spec of BRUTE_CIPHERS) {
          let output;
          try {
            output = createStreamFor(spec, key, iv).xor(sample);
          } catch {
            continue;
          }
          if (!looksLikeRpf2(output)) continue;

          const xorHex = xorByte.toString(16).padStart(2, '0');
          hits.push({
            id: `brute(skip=${skip},xor=0x${xorHex},trim=${trim}) + ${spec.id}`,
            label: `brute-forced key (skip ${skip}, xor 0x${xorHex}, trim ${trim}) with ${spec.id}`,
            spec,
            // Copy: `unmasked` is reused for every xor value, so a subarray would
            // silently change under the caller afterwards.
            key: Buffer.from(key),
            iv: Buffer.from(iv),
            skip,
            xorByte,
            trim,
          });

          if (hits.length >= maxHits) return { raw, hits };
        }
      }
    }
  }

  return { raw, hits };
}
