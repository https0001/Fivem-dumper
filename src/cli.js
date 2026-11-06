#!/usr/bin/env node
// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// CLI entry point.
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { AUTHOR, COMMUNITY, COPYRIGHT, DISCORD, DISCLAIMER } from './brand.js';
import { FxServerClient, FxServerError } from './fxserver.js';
import { resolveServer } from './resolver.js';
import { dumpResource, filterResources, mapWithConcurrency } from './dumper.js';
import {
  color,
  ensureDir,
  humanBytes,
  log,
  padEnd,
  padStart,
  safeName,
  setVerbose,
} from './util.js';

const VERSION = '1.0.0';
const DEFAULTS = {
  out: './dump',
  concurrency: 3,
  timeout: 30_000,
  streamDecrypt: 'auto',
};

/* --------------------------------------------------------------- arg parse */

function parseArgs(argv) {
  const opts = {
    server: '',
    out: DEFAULTS.out,
    only: [],
    exclude: [],
    streams: false,
    streamDecrypt: DEFAULTS.streamDecrypt,
    concurrency: DEFAULTS.concurrency,
    timeout: DEFAULTS.timeout,
    token: process.env.CITIZENFX_TOKEN ?? '',
    insecure: false,
    dryRun: false,
    infoOnly: false,
    keepArchive: false,
    diagnose: false,
    verbose: false,
    help: false,
    version: false,
  };

  const listValue = (value) =>
    String(value)
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const [flag, inline] = arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, undefined];
    const takeValue = () => {
      if (inline !== undefined) return inline;
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) {
        throw new Error(`option ${flag} expects a value`);
      }
      i += 1;
      return next;
    };

    switch (flag) {
      case '--server':
      case '-s':
        opts.server = takeValue();
        break;
      case '--out':
      case '-o':
        opts.out = takeValue();
        break;
      case '--only':
        opts.only.push(...listValue(takeValue()));
        break;
      case '--exclude':
        opts.exclude.push(...listValue(takeValue()));
        break;
      case '--streams':
        opts.streams = true;
        break;
      case '--stream-decrypt':
        opts.streamDecrypt = takeValue();
        if (!['auto', 'always', 'never'].includes(opts.streamDecrypt)) {
          throw new Error(`--stream-decrypt must be auto|always|never`);
        }
        break;
      case '--concurrency':
      case '-c':
        opts.concurrency = Number(takeValue());
        if (!Number.isFinite(opts.concurrency) || opts.concurrency < 1) {
          throw new Error('--concurrency must be a positive number');
        }
        break;
      case '--timeout':
        opts.timeout = Number(takeValue());
        if (!Number.isFinite(opts.timeout) || opts.timeout < 1000) {
          throw new Error('--timeout must be at least 1000ms');
        }
        break;
      case '--token':
        opts.token = takeValue();
        break;
      case '--insecure':
        opts.insecure = true;
        break;
      case '--dry-run':
        opts.dryRun = true;
        break;
      case '--info':
        opts.infoOnly = true;
        break;
      case '--keep-archive':
        opts.keepArchive = true;
        break;
      case '--diagnose':
        opts.diagnose = true;
        break;
      case '--verbose':
      case '-v':
        opts.verbose = true;
        break;
      case '--help':
      case '-h':
        opts.help = true;
        break;
      case '--version':
        opts.version = true;
        break;
      default:
        throw new Error(`unknown option: ${arg}`);
    }
  }

  return opts;
}

function printHelp() {
  const out = (line = '') => process.stdout.write(`${line}\n`);
  out(`${color.bold(`fivem-dumper ${VERSION}`)} — unpack a FiveM server's client resources`);
  out(`${color.dim(`by ${AUTHOR} · ${COPYRIGHT}`)}`);
  out(`${color.cyan(DISCORD)}`);
  out();
  out(`${color.bold('Usage')}`);
  out('  node src/cli.js --server <host[:port]|url|cfx.re/join/code> [options]');
  out();
  out(`${color.bold('Required')}`);
  out('  -s, --server <addr>       Address, URL, cfx.re/join/<code>, or fivem:// link');
  out();
  out(`${color.bold('Options')}`);
  out('  -o, --out <dir>           Output directory                     (default ./dump)');
  out('      --only <a,b>          Only these resources');
  out('      --exclude <a,b>       Skip these resources');
  out('      --streams             Also fetch stream/ assets (.ytd, .ydr, ...)');
  out('      --stream-decrypt <m>  auto | always | never               (default auto)');
  out('  -c, --concurrency <n>     Parallel resources                     (default 3)');
  out('      --timeout <ms>        Idle socket timeout                    (default 30000)');
  out('      --token <token>       X-CitizenFX-Token for getConfiguration');
  out('      --insecure            Do not verify TLS certificates');
  out('      --keep-archive        Keep the downloaded .rpf next to its files');
  out('      --diagnose            On an undecryptable payload, save a sample + probe report');
  out('      --dry-run             List what would be fetched, download nothing');
  out('      --info                Print the public /info.json only (no client needed)');
  out('  -v, --verbose             Per-file detail');
  out('  -h, --help                This text');
  out('      --version             Print version');
  out();
  out(`${color.bold('How the server authorises the request')}`);
  out('  FXServer answers /client?method=getConfiguration only for clients it can see,');
  out('  matched by X-CitizenFX-Token or by source IP with a completed handshake.');
  out('  So join the server with the FiveM client first and keep it connected, then run');
  out('  this tool from the same machine. Or pass --token if you have a connection token.');
  out();
  out(`${color.bold('What you get')}`);
  out('  The resource package delivered to clients: fxmanifest/__resource.lua,');
  out('  client_script, shared_script, `files` entries and maps. Server-only scripts');
  out('  and `server_only` resources are never sent to clients and cannot be obtained.');
  out();
  out(color.yellow(`  ${DISCLAIMER}`));
  out(color.dim(`  ${DISCORD}`));
}

/* ------------------------------------------------------------------ pretty */

function printServerLine(info, client) {
  if (!info) {
    log.info(`  ${color.dim('server name     :')} ${color.dim('(info.json unavailable)')}`);
    return;
  }
  log.info(`  ${color.dim('server name     :')} ${info.vars?.sv_hostname ?? '(unnamed)'}`);
  const clients = info.vars?.sv_maxclients ? `${info.clients ?? '?'}/${info.vars.sv_maxclients}` : '?';
  log.info(`  ${color.dim('players         :')} ${clients}`);
  log.info(`  ${color.dim('resources       :')} ${Array.isArray(info.resources) ? info.resources.length : '?'}`);
  log.info(`  ${color.dim('build           :')} ${info.vars?.version ?? info.server ?? '?'}`);
}

/* -------------------------------------------------------------------- main */

export async function main(argv = process.argv.slice(2)) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (error) {
    log.err(error.message);
    process.stderr.write(`Try --help\n`);
    return 2;
  }

  if (opts.help) {
    printHelp();
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`fivem-dumper ${VERSION} · by ${AUTHOR}\n${DISCORD}\n`);
    return 0;
  }
  if (!opts.server) {
    log.err('no --server given');
    process.stderr.write('Try --help\n');
    return 2;
  }

  setVerbose(opts.verbose);

  let base;
  let resolved = null;
  try {
    const resolution = await resolveServer(opts.server);
    base = resolution.base;
    resolved = resolution.resolved;
  } catch (error) {
    log.err(error.message);
    return 2;
  }

  const serverLabel = safeName(`${base.hostname}_${base.port}`, 'server');
  const outDir = path.resolve(opts.out, serverLabel);
  const tmpDir = path.join(outDir, '.tmp');

  const client = new FxServerClient({
    base,
    timeout: opts.timeout,
    insecure: opts.insecure,
    token: opts.token,
    concurrency: opts.concurrency,
  });

  const signal = { aborted: false };
  let interrupted = 0;
  process.on('SIGINT', () => {
    interrupted += 1;
    if (interrupted === 1) {
      signal.aborted = true;
      log.warn('interrupt: finishing in-flight files, then stopping (Ctrl+C again to force)');
    } else {
      process.exit(130);
    }
  });

  process.stderr.write(
    `\n${color.bold(`fivem-dumper ${VERSION}`)}${color.dim(`  ·  by ${AUTHOR}`)}\n`,
  );
  process.stderr.write(`  ${color.cyan(DISCORD)}\n`);
  process.stderr.write(`  ${color.dim(DISCLAIMER)}\n`);
  if (resolved) {
    log.info(
      `  ${color.dim('resolved        :')} ${opts.server} -> ${resolved.endpoint}` +
        `${resolved.hostname ? color.dim(`  (${resolved.hostname.trim()})`) : ''}`,
    );
  }
  log.info(`  ${color.dim('server          :')} ${client.displayUrl}`);
  log.info(`  ${color.dim('output          :')} ${outDir}`);
  process.stderr.write('\n');

  try {
    log.step('GET /info.json');
    const info = await client.getInfo();
    printServerLine(info, client);

    if (opts.infoOnly) {
      const names = Array.isArray(info?.resources) ? info.resources : [];
      process.stderr.write(`\n${color.bold('resources')} (${names.length})\n`);
      for (const name of names) process.stdout.write(`  ${name}\n`);
      if (names.length === 0) {
        log.warn('no resources listed (or /info.json is unavailable)');
      }
      return 0;
    }

    // getConfiguration may need a moment right after joining, or after a rate limit.
    let config;
    let attempts = 0;
    for (;;) {
      attempts += 1;
      log.step('POST /client (method=getConfiguration)');
      try {
        config = await client.getConfiguration({
          resources: opts.only.map((name) => name),
        });
        break;
      } catch (error) {
        const retriable =
          error instanceof FxServerError &&
          /still connecting|rate limit/i.test(error.message) &&
          attempts < 3;

        if (!retriable) throw error;

        const waitMs = 5000 * attempts;
        log.warn(`${error.message.split('\n')[0]} — retrying in ${waitMs / 1000}s (${attempts}/3)`);
        await new Promise((resolve) => setTimeout(resolve, waitMs));
      }
    }

    const resources = filterResources(config.resources, {
      only: opts.only,
      exclude: opts.exclude,
    });

    if (resources.length === 0) {
      log.warn('the server returned no resources');
      if (Array.isArray(info?.resources) && info.resources.length > 0) {
        log.info(
          `  the public /info.json lists ${info.resources.length} resource(s), so the filter may be too narrow`,
        );
      }
      return 1;
    }

    process.stderr.write(
      `\n${color.bold('plan')} — ${resources.length} resource(s)` +
        `, ${opts.streams ? 'with' : 'without'} stream assets\n`,
    );

    if (opts.dryRun) {
      const width = Math.max(...resources.map((r) => String(r.name).length), 12);
      for (const resource of resources) {
        const files = Object.keys(resource.files ?? {}).length;
        const streams = Object.keys(resource.streamFiles ?? {}).length;
        const encrypted = resource.uri ? color.dim(' keyed') : '';
        process.stdout.write(
          `  ${padEnd(resource.name, width)}  ${padStart(files, 2)} archive(s)  ${padStart(streams, 4)} stream(s)${encrypted}\n`,
        );
      }
      process.stderr.write(`\n${color.dim('dry run: nothing downloaded')}\n`);
      return 0;
    }

    await ensureDir(tmpDir);

    const startedAt = Date.now();
    let completed = 0;
    const width = Math.max(...resources.map((r) => String(r.name).length), 12);

    const results = await mapWithConcurrency(
      resources,
      opts.concurrency,
      async (resource) => {
        const result = await dumpResource({
          client,
          resource,
          outDir,
          tmpDir,
          options: opts,
          signal,
          defaultFileServer: config.fileServer,
          progress: (event) => log.detail(`${resource.name}: ${event.phase} ${event.fileName}`),
        });

        completed += 1;
        const counter = `[${padStart(completed, String(resources.length).length)}/${resources.length}]`;

        if (result.skipped) {
          process.stderr.write(
            `${counter} ${color.dim(padEnd(result.name, width))} ${color.dim('skipped')} ${color.dim(result.notes[0] ?? '')}\n`,
          );
        } else if (result.ok) {
          process.stderr.write(
            `${counter} ${color.green(padEnd(result.name, width))} ${padStart(result.files, 4)} files ${padStart(humanBytes(result.bytes), 9)}\n`,
          );
        } else {
          process.stderr.write(
            `${counter} ${color.red(padEnd(result.name, width))} ${color.red('failed')} ${color.dim(result.errors[0] ?? '')}\n`,
          );
        }

        if (opts.verbose) {
          for (const note of result.notes) log.detail(`${result.name}: ${note}`);
          for (const error of result.errors) log.detail(`${result.name}: ${error}`);
        }

        return result;
      },
      signal,
    );

    const finished = results.filter(Boolean);
    const okCount = finished.filter((r) => r.ok).length;
    const skipCount = finished.filter((r) => r.skipped).length;
    const failed = finished.filter((r) => !r.ok && !r.skipped);
    const totalFiles = finished.reduce((sum, r) => sum + r.files, 0);
    const totalBytes = finished.reduce((sum, r) => sum + r.bytes + r.streams.bytes, 0);
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);

    const manifest = {
      tool: `fivem-dumper/${VERSION}`,
      author: AUTHOR,
      copyright: COPYRIGHT,
      discord: DISCORD,
      community: COMMUNITY,
      server: client.displayUrl,
      serverName: info?.vars?.sv_hostname ?? null,
      fetchedAt: new Date().toISOString(),
      aborted: signal.aborted,
      options: {
        only: opts.only,
        exclude: opts.exclude,
        streams: opts.streams,
        streamDecrypt: opts.streamDecrypt,
        keepArchive: opts.keepArchive,
      },
      totals: {
        resources: finished.length,
        ok: okCount,
        skipped: skipCount,
        failed: failed.length,
        files: totalFiles,
        bytes: totalBytes,
      },
      resources: finished,
    };

    const manifestPath = path.join(outDir, 'manifest.json');
    await fsp.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    await fsp.rm(tmpDir, { recursive: true, force: true }).catch(() => {});

    process.stderr.write('\n');
    log.info(
      `${color.bold('summary')}  ${color.green(`${okCount} ok`)}` +
        `${failed.length ? `, ${color.red(`${failed.length} failed`)}` : ''}` +
        `${skipCount ? `, ${color.dim(`${skipCount} skipped`)}` : ''}` +
        ` · ${totalFiles} files · ${humanBytes(totalBytes)} · ${elapsed}s`,
    );
    log.info(`${color.dim('manifest')} ${manifestPath}`);
    log.info(`${color.dim('project')}  ${DISCORD}`);

    if (failed.length > 0) {
      log.info('');
      for (const resource of failed) {
        log.err(`${resource.name}: ${resource.errors[0] ?? 'unknown error'}`);
      }
    }

    if (signal.aborted) return 130;
    return failed.length > 0 ? 1 : 0;
  } catch (error) {
    process.stderr.write('\n');
    log.err(error.message);
    return 2;
  } finally {
    client.dispose();
  }
}

const directly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (directly) {
  process.exitCode = await main();
}
