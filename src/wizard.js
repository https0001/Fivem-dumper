// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Easy mode: double-click start.cmd and answer a few questions.
// Everything collected here becomes the same flags the advanced CLI takes.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { AUTHOR, COPYRIGHT, DISCORD, DISCLAIMER } from './brand.js';
import { FxServerClient } from './fxserver.js';
import { main } from './cli.js';
import { resolveServer } from './resolver.js';
import { loadSettings, saveSettings } from './settings.js';
import { color, safeName } from './util.js';

const VERSION = '1.0.0';
const RULE = '─'.repeat(58);

/* --------------------------------------------------------------- prompting
 * A tiny line reader instead of node:readline. readline drops lines when input
 * arrives faster than the questions are asked (pasting, piping, automation),
 * which is exactly how people feed this thing. This queues every line instead.
 */
const pendingLines = [];
let waiting = null;
let stdinBuffer = '';

function attachStdin() {
  if (!process.stdin.isTTY) process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    stdinBuffer += chunk;
    let index;
    while ((index = stdinBuffer.indexOf('\n')) >= 0) {
      const line = stdinBuffer.slice(0, index).replace(/\r$/, '');
      stdinBuffer = stdinBuffer.slice(index + 1);
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve(line);
      } else {
        pendingLines.push(line);
      }
    }
  });
  process.stdin.on('end', () => {
    if (waiting) {
      const resolve = waiting;
      waiting = null;
      resolve('');
    }
  });
}

function ask(question, fallback = '') {
  process.stdout.write(question);
  return new Promise((resolve) => {
    const deliver = (line) => {
      const trimmed = String(line).trim();
      resolve(trimmed === '' ? fallback : trimmed);
    };
    if (pendingLines.length > 0) deliver(pendingLines.shift());
    else waiting = deliver;
  });
}

const isYes = (value) => /^(y|yes|ok)$/i.test(String(value).trim());

/* ----------------------------------------------------------------- helpers */

export function buildRunArgs({ base, streams = false, onlyName = '', out = './dump' }) {
  const args = ['--server', base.origin, '--out', out || './dump'];
  if (streams) args.push('--streams');
  if (onlyName) args.push('--only', onlyName);
  return args;
}

export function outputDirFor(base, out = './dump') {
  return path.resolve(out || './dump', safeName(`${base.hostname}_${base.port}`, 'server'));
}

function openFolder(target) {
  const opener =
    process.platform === 'win32'
      ? 'explorer.exe'
      : process.platform === 'darwin'
        ? 'open'
        : 'xdg-open';
  try {
    const child = spawn(opener, [target], { detached: true, stdio: 'ignore' });
    child.on('error', () => {});
    child.unref();
  } catch {
    /* opening the folder is a nicety, never a failure */
  }
}

function banner() {
  process.stdout.write(`\n${RULE}\n`);
  process.stdout.write(`  ${color.bold('fivem-dumper')} ${color.dim(`v${VERSION}`)}\n`);
  process.stdout.write(`  ${color.dim(`by ${AUTHOR} · ${COPYRIGHT}`)}\n`);
  process.stdout.write(`  ${color.cyan(DISCORD)}\n`);
  process.stdout.write(`  ${color.dim(DISCLAIMER)}\n`);
  process.stdout.write(`${RULE}\n\n`);
  process.stdout.write('  Before you start: join the server in FiveM and keep it open.\n');
  process.stdout.write('  Then answer the questions below (press Enter to accept a default).\n\n');
}

/* -------------------------------------------------------------------- main */

async function run() {
  banner();
  attachStdin();

  const saved = await loadSettings();

  // 1) server address: plain IP, URL, or a cfx.re/join code (keep asking until it works)
  let base = null;
  let resolved = null;
  let serverInput = '';
  for (;;) {
    const answer = await ask(
      `1) Server address or cfx.re/join code ${color.dim(`[${saved.server || '127.0.0.1:30120'}]`)}: `,
      saved.server || '127.0.0.1:30120',
    );
    try {
      serverInput = String(answer).replace(/["']/g, '');
      const resolution = await resolveServer(serverInput);
      base = resolution.base;
      resolved = resolution.resolved;
      if (resolved) {
        process.stdout.write(
          `   ${color.green('✓')} ${resolved.code} -> ${resolved.endpoint}\n`,
        );
      }
      break;
    } catch (error) {
      process.stdout.write(`   ${color.red('x')} ${error.message}\n`);
    }
  }

  // show something back so a typo is obvious immediately
  const client = new FxServerClient({ base, timeout: 8000 });
  const info = await client.getInfo();
  client.dispose();

  const names = Array.isArray(info?.resources) ? info.resources : [];
  if (info) {
    const label = info.vars?.sv_hostname || resolved?.hostname || '(unnamed)';
    process.stdout.write(`   ${color.green('✓')} Server: ${String(label).trim()}\n`);
    process.stdout.write(`   ${color.dim(`Resources: ${names.length}`)}\n\n`);
  } else {
    process.stdout.write(`   ${color.yellow('!')} Could not read server info - continuing anyway.\n\n`);
  }

  // 2) stream assets
  const streamsAnswer = await ask(
    `2) Include stream assets (vehicles/maps/clothing)? Bigger download ${color.dim(`[${saved.streams ? 'y' : 'n'}]`)}: `,
    saved.streams ? 'y' : 'n',
  );
  const streams = isYes(streamsAnswer);

  // 3) everything, or one resource
  const scopeAnswer = await ask(
    `3) Resource name, or leave blank for everything ${color.dim('[all]')}: `,
    '',
  );

  let onlyName = '';
  if (scopeAnswer) {
    onlyName = String(scopeAnswer).replace(/["']/g, '');
  } else if (names.length > 0) {
    const preview = names.slice(0, 12).join(' · ');
    process.stdout.write(`   ${color.dim(`Examples: ${preview}${names.length > 12 ? ' …' : ''}`)}\n`);
  }
  process.stdout.write('\n');

  // 4) confirm
  process.stdout.write(
    `${color.bold('Plan:')} ${onlyName ? `single resource: ${onlyName}` : `all resources (${names.length || '?'})`}\n`,
  );
  process.stdout.write(`      Streams: ${streams ? 'yes' : 'no'}\n\n`);

  const go = await ask(`Start? ${color.dim('[Y/n]')}: `, 'y');
  if (!isYes(go)) {
    process.stdout.write('\nCancelled.\n');
    return 0;
  }

  await saveSettings({
    // remember exactly what was typed, so a join code keeps working as-is
    server: serverInput || `${base.hostname}:${base.port}`,
    streams,
    only: onlyName,
    out: saved.out || './dump',
  });

  // hand over to the real CLI; the flags are just hidden from the user now
  const code = await main(buildRunArgs({ base, streams, onlyName, out: saved.out || './dump' }));

  const outDir = outputDirFor(base, saved.out || './dump');
  process.stdout.write('\n');
  if (code === 0) {
    process.stdout.write(`${RULE}\n`);
    process.stdout.write(`  ${color.green('Done ✓')}  Files are in:\n  ${outDir}\n`);
    process.stdout.write(`${RULE}\n`);

    const openIt = await ask(`\nOpen the folder? ${color.dim('[Y/n]')}: `, 'y');
    if (isYes(openIt)) openFolder(outDir);
  } else {
    process.stdout.write(`  ${color.yellow('Finished with errors')} - see the messages above.\n`);
  }

  process.stdout.write(`  ${color.dim(`${COPYRIGHT} · ${DISCORD}`)}\n`);
  process.stdout.write(`  ${color.dim(DISCLAIMER)}\n`);

  return code;
}

const directly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (directly) {
  process.exitCode = await run();
}
