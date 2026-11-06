// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Thin HTTP client for the two FXServer endpoints a dumper needs:
//   POST /client  (method=getConfiguration)  -> what the client must download
//   GET  /files/<resource>/<file>?hash=<sha1> -> the payload itself
//
// No external dependencies: node:http/https gives us streaming, idle timeouts,
// redirect handling and a way to opt out of TLS verification for self-signed hosts.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';

import { joinUrl } from './util.js';

export const USER_AGENT = 'CitizenFX/1';
const MAX_REDIRECTS = 5;

export class FxServerError extends Error {
  constructor(message, { status = 0, body = '' } = {}) {
    super(message);
    this.name = 'FxServerError';
    this.status = status;
    this.body = body;
  }
}

function readAll(stream, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total <= limit) chunks.push(chunk);
    });
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

export class FxServerClient {
  /**
   * @param {object} options
   * @param {URL} options.base                e.g. http://1.2.3.4:30120
   * @param {number} [options.timeout]        idle socket timeout in ms
   * @param {boolean} [options.insecure]      skip TLS certificate verification
   * @param {string} [options.token]          value for X-CitizenFX-Token
   * @param {number} [options.concurrency]    max sockets for keep-alive agents
   */
  constructor({ base, timeout = 30_000, insecure = false, token = '', concurrency = 4 }) {
    this.base = base;
    this.timeout = timeout;
    this.insecure = insecure;
    this.token = token;
    this.agents = {
      'http:': new http.Agent({ keepAlive: true, maxSockets: Math.max(1, concurrency) }),
      'https:': new https.Agent({
        keepAlive: true,
        maxSockets: Math.max(1, concurrency),
        rejectUnauthorized: !insecure,
      }),
    };
  }

  get origin() {
    return this.base.origin;
  }

  get displayUrl() {
    return this.base.href.replace(/\/+$/, '');
  }

  /** Server identity / resource names from the public /info.json endpoint. */
  async getInfo() {
    try {
      const { res } = await this.#send(joinUrl(this.origin, 'info.json'), {
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      });
      if (res.statusCode !== 200) {
        await readAll(res).catch(() => {});
        return null;
      }
      const text = await readAll(res, 4 * 1024 * 1024);
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  /**
   * Ask the server what a connected client would need to download.
   * Requires this machine to look like a connected, validated client.
   */
  async getConfiguration({ resources = [] } = {}) {
    const form = new URLSearchParams();
    form.set('method', 'getConfiguration');
    if (resources.length > 0) form.set('resources', resources.join(';'));
    const body = form.toString();

    const headers = {
      'User-Agent': USER_AGENT,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    if (this.token) headers['X-CitizenFX-Token'] = this.token;

    const { res } = await this.#send(joinUrl(this.origin, 'client'), {
      method: 'POST',
      headers,
      body,
    });

    const text = await readAll(res, 16 * 1024 * 1024);

    if (res.statusCode === 405) {
      throw new FxServerError('/client is POST-only; this endpoint does not look like FXServer', {
        status: 405,
        body: text,
      });
    }

    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new FxServerError(`unparseable response from /client (HTTP ${res.statusCode})`, {
        status: res.statusCode,
        body: text.slice(0, 400),
      });
    }

    if (payload && typeof payload.error === 'string') {
      const hints = {
        'Not a valid client.':
          'The server only answers clients it can see. Join the server with the FiveM client ' +
          'first (stay connected), or pass --token with a connection token.',
        'Client is still connecting.':
          'A client from this IP is still handshaking. Wait until you are fully in the server, then retry.',
        'Rate limit exceeded.':
          'Too many configuration requests from this client token. Wait a little and retry.',
      };
      const hint = hints[payload.error] ?? '';
      throw new FxServerError(
        `${payload.error}${hint ? `\n       ${hint}` : ''}`,
        { status: res.statusCode, body: text },
      );
    }

    if (!payload || !Array.isArray(payload.resources)) {
      throw new FxServerError('server response has no resources array', {
        status: res.statusCode,
        body: text.slice(0, 400),
      });
    }

    return payload;
  }

  /**
   * Stream one resource file to `destination`.
   * Returns { sha1, size, url, contentLength } where sha1 is of the bytes as served
   * (i.e. before any decryption).
   */
  async downloadFile({ resourceName, fileName, hash, destination, fileServer }) {
    const base = fileServer ? expandFileServer(fileServer, this.base) : joinUrl(this.origin, 'files');
    let url = joinUrl(base, resourceName, fileName);
    if (hash) url += `?hash=${encodeURIComponent(hash)}`;

    const { res } = await this.#send(url, {
      headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
    });

    if (res.statusCode !== 200) {
      const text = await readAll(res, 8 * 1024).catch(() => '');
      const detail = text.trim().slice(0, 300);
      throw new FxServerError(
        `GET ${url} -> HTTP ${res.statusCode}${detail ? `: ${detail}` : ''}`,
        { status: res.statusCode, body: detail },
      );
    }

    const contentLength = Number(res.headers['content-length'] ?? 0) || 0;
    const hashStream = crypto.createHash('sha1');
    const handle = await fsp.open(destination, 'w');
    let size = 0;

    try {
      for await (const chunk of res) {
        hashStream.update(chunk);
        await handle.write(chunk, 0, chunk.length);
        size += chunk.length;
      }
    } finally {
      await handle.close();
    }

    return {
      sha1: hashStream.digest('hex'),
      size,
      url,
      contentLength,
      truncated: contentLength > 0 && contentLength !== size,
    };
  }

  dispose() {
    for (const agent of Object.values(this.agents)) agent.destroy();
  }

  /* ------------------------------------------------------------- internals */

  #send(url, options = {}) {
    return this.#sendWithRedirects(String(url), options, 0);
  }

  #sendWithRedirects(url, options, redirects) {
    return new Promise((resolve, reject) => {
      let target;
      try {
        target = new URL(url);
      } catch {
        reject(new FxServerError(`invalid URL: ${url}`));
        return;
      }

      const lib = target.protocol === 'https:' ? https : http;
      const agent = this.agents[target.protocol];
      if (!agent) {
        reject(new FxServerError(`unsupported protocol ${target.protocol}`));
        return;
      }

      const headers = { ...(options.headers ?? {}) };
      const requestOptions = {
        method: options.method ?? 'GET',
        headers,
        agent,
        rejectUnauthorized: !this.insecure,
        // Some FXServer deployments sit behind NAT/proxies that choke on IPv6
        // literals; leaving this default keeps DNS behaviour predictable.
      };

      const req = lib.request(target, requestOptions, (res) => {
        res.setTimeout(this.timeout, () => {
          res.destroy(new Error(`response stalled for ${this.timeout}ms`));
        });

        const status = res.statusCode ?? 0;
        const location = res.headers.location;

        if (status >= 300 && status < 400 && location) {
          res.resume();
          if (redirects >= MAX_REDIRECTS) {
            reject(new FxServerError(`too many redirects (${MAX_REDIRECTS})`, { status }));
            return;
          }
          this.#sendWithRedirects(new URL(location, target).href, options, redirects + 1).then(
            resolve,
            reject,
          );
          return;
        }

        resolve({ res, url: target });
      });

      req.setTimeout(this.timeout, () => {
        req.destroy(new Error(`request timed out after ${this.timeout}ms`));
      });

      req.on('error', (error) => {
        reject(
          error instanceof FxServerError
            ? error
            : new FxServerError(`request to ${target.origin} failed: ${error.message}`),
        );
      });

      if (options.body) req.write(options.body);
      req.end();
    });
  }
}

/**
 * FXServer's file-server template is "https://%s/files", where %s stands for the
 * endpoint the client connected to (so the scheme in the template is only a
 * placeholder too). Per-resource overrides (fileserver_add) may be a template or
 * a concrete base URL such as "https://cdn.example.com/files".
 */
function expandFileServer(template, base) {
  const text = String(template).trim().replace(/\/+$/, '');
  if (!text.includes('%s')) return text;

  const replaced = text.replace('%s', base.host);
  try {
    const url = new URL(replaced);
    // The scheme belongs to the connection, not to the template.
    url.protocol = base.protocol;
    return `${url.origin}${url.pathname}`;
  } catch {
    return replaced;
  }
}
