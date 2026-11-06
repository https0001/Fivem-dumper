// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Small shared helpers: path safety, URL normalisation, sizes, logging, hashing.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

/* ------------------------------------------------------------------ colours */

const COLOR_ENABLED =
  !process.env.NO_COLOR && process.env.TERM !== 'dumb' && Boolean(process.stdout.isTTY);

const wrap = (code) => (s) =>
  COLOR_ENABLED ? `\u001b[${code}m${s}\u001b[0m` : String(s);

export const color = {
  dim: wrap(2),
  bold: wrap(1),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  cyan: wrap(36),
};

/* ----------------------------------------------------------------- logging */

let verbose = false;

export function setVerbose(value) {
  verbose = Boolean(value);
}

export const log = {
  info(msg) {
    process.stderr.write(`${msg}\n`);
  },
  ok(msg) {
    process.stderr.write(`${color.green('ok  ')} ${msg}\n`);
  },
  warn(msg) {
    process.stderr.write(`${color.yellow('warn')} ${msg}\n`);
  },
  err(msg) {
    process.stderr.write(`${color.red('fail')} ${msg}\n`);
  },
  step(msg) {
    process.stderr.write(`${color.cyan('  ->')} ${msg}\n`);
  },
  detail(msg) {
    if (verbose) process.stderr.write(`${color.dim(`     ${msg}`)}\n`);
  },
};

/* ------------------------------------------------------------------- misc */

export function humanBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* -------------------------------------------------------------- paths/urls */

/**
 * Reject anything that could escape the output directory once joined.
 * Returns a safe single path segment (or a safe relative path if allowDirs).
 */
export function safeRelPath(raw, { allowDirs = true } = {}) {
  const str = String(raw ?? '')
    .replace(/\\/g, '/')
    .replace(/\0/g, '')
    .trim();

  if (!str) return null;

  const parts = str
    .split('/')
    .filter((part) => part !== '' && part !== '.' && part !== '..')
    // Strip characters that are illegal on Windows and would make writes fail.
    .map((part) => part.replace(/[<>:"|?*\u0000-\u001f]/g, '_').replace(/[. ]+$/, ''))
    .filter((part) => part.length > 0);

  if (parts.length === 0) return null;
  if (!allowDirs) return parts[parts.length - 1];
  return parts.join('/');
}

/** Filesystem-safe folder name for a server/resource label. */
export function safeName(raw, fallback = 'unnamed') {
  const cleaned = String(raw ?? '')
    .replace(/^\.+/, '')
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_')
    .replace(/[. ]+$/, '')
    .trim();
  return cleaned || fallback;
}

/**
 * Accepts "1.2.3.4", "1.2.3.4:30120", "http://host:30120", "host".
 * FiveM's default game port is 30120, so that is assumed when omitted.
 */
export function normalizeServer(input, { defaultPort = 30120 } = {}) {
  let raw = String(input ?? '').trim();
  if (!raw) throw new Error('no server address given');

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    raw = `http://${raw}`;
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`could not parse server address: ${input}`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`unsupported protocol "${url.protocol}" (use http:// or https://)`);
  }

  if (!url.port) url.port = String(defaultPort);
  url.pathname = url.pathname.replace(/\/+$/, '');
  url.search = '';
  url.hash = '';
  return url;
}

/** Join a base URL and already-decoded path segments, encoding each segment. */
export function joinUrl(base, ...segments) {
  const trimmed = String(base).replace(/\/+$/, '');
  const encoded = segments
    .filter((s) => s !== undefined && s !== null && s !== '')
    .map((s) => String(s).split('/').map(encodeURIComponent).join('/'));
  return encoded.length ? `${trimmed}/${encoded.join('/')}` : trimmed;
}

/* -------------------------------------------------------------------- fs */

export async function ensureDir(dir) {
  await fsp.mkdir(dir, { recursive: true });
}

export async function exists(target) {
  try {
    await fsp.access(target, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function isDirectory(target) {
  try {
    return (await fsp.stat(target)).isDirectory();
  } catch {
    return false;
  }
}

export async function removeQuiet(target) {
  try {
    await fsp.rm(target, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

export async function fileSize(target) {
  try {
    return (await fsp.stat(target)).size;
  } catch {
    return 0;
  }
}

/* ----------------------------------------------------------------- hashing */

export function sha1(buffer) {
  return crypto.createHash('sha1').update(buffer).digest('hex');
}

/** Streaming SHA-1 of a file, used to verify downloads against the manifest hash. */
export async function sha1File(filePath) {
  const hash = crypto.createHash('sha1');
  const handle = await fsp.open(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead <= 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

export function padEnd(value, width) {
  const str = String(value);
  return str.length >= width ? str : str + ' '.repeat(width - str.length);
}

export function padStart(value, width) {
  const str = String(value);
  return str.length >= width ? str : ' '.repeat(width - str.length) + str;
}

export { path };
