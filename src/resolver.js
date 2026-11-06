// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Accepts friendly server references, not just raw addresses:
//
//   194.50.0.77:30120
//   http://194.50.0.77:30120
//   cfx.re/join/p39bpy
//   https://cfx.re/join/p39bpy
//   fivem://connect/cfx.re/join/p39bpy
//   fivem://connect/194.50.0.77:30120
//   p39bpy            (bare join code, tried against the lookup API)
//
// cfx.re/join/<code> is a web page, not a redirect, so the code is resolved through
// the same lookup endpoint the server list uses.
import { normalizeServer } from './util.js';

const LOOKUP_API = 'https://frontend.cfx-services.net/api/servers/single/';
const DEEP_LINK = /^fivem:\/\/connect\/(.+)$/i;
const JOIN_URL = /^(?:https?:\/\/)?(?:www\.)?cfx\.re\/join\/([a-z0-9]+)\/?$/i;
const JOIN_QUERY = /^(?:https?:\/\/)?(?:www\.)?cfx\.re\/join\/?\?code=([a-z0-9]+)/i;
const BARE_CODE = /^[a-z0-9]{4,10}$/i;

/** Pull a join code out of any of the accepted forms, or null. */
export function extractJoinCode(input) {
  const text = String(input ?? '').trim();
  if (!text) return null;

  const deepLink = DEEP_LINK.exec(text);
  if (deepLink) {
    const inner = deepLink[1].trim();
    const nested = extractJoinCode(inner);
    return nested; // null when the link already carries host:port
  }

  const urlMatch = JOIN_URL.exec(text) ?? JOIN_QUERY.exec(text);
  if (urlMatch) return urlMatch[1].toLowerCase();

  if (BARE_CODE.test(text)) return text.toLowerCase();

  return null;
}

/** True when the input is a cfx.re join link rather than a plain address. */
export function looksLikeJoinUrl(input) {
  return /cfx\.re/i.test(String(input ?? ''));
}

/**
 * Ask the server-list API what endpoint a join code points at.
 * @returns {Promise<{endpoint: string, hostname: string|null}>}
 */
export async function resolveJoinCode(code, { timeout = 10_000, fetchImpl = fetch } = {}) {
  const url = `${LOOKUP_API}${encodeURIComponent(code)}`;

  let res;
  try {
    res = await fetchImpl(url, {
      headers: { accept: 'application/json', 'user-agent': 'fivem-dumper' },
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    throw new Error(`join-code lookup failed (${error.message})`);
  }

  if (!res.ok) {
    throw new Error(`join code "${code}" not found (HTTP ${res.status})`);
  }

  let json;
  try {
    json = await res.json();
  } catch {
    throw new Error(`join-code lookup returned non-JSON for "${code}"`);
  }

  const endpoints = json?.Data?.connectEndPoints;
  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    throw new Error(`server "${code}" is offline or private (no connect endpoints)`);
  }

  return {
    endpoint: String(endpoints[0]),
    hostname: json?.Data?.hostname ?? null,
  };
}

/**
 * Turn any accepted input into a normalised base URL.
 * @returns {Promise<{base: URL, resolved: null | {code: string, endpoint: string, hostname: string|null}}>}
 */
export async function resolveServer(input, options = {}) {
  const text = String(input ?? '').trim();
  if (!text) throw new Error('no server address given');

  const deepLink = DEEP_LINK.exec(text);
  const target = deepLink ? deepLink[1].trim() : text;

  const code = extractJoinCode(target);

  if (code) {
    try {
      const { endpoint, hostname } = await resolveJoinCode(code, options);
      return {
        base: normalizeServer(endpoint),
        resolved: { code, endpoint, hostname },
      };
    } catch (error) {
      // An explicit cfx.re link should fail loudly; a bare word might just be a hostname.
      if (looksLikeJoinUrl(text) || deepLink) throw error;
    }
  }

  if (deepLink) {
    return { base: normalizeServer(target), resolved: null };
  }

  return { base: normalizeServer(text), resolved: null };
}
