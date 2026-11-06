// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Last-used answers, so the wizard is a few Enter presses after the first run.
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const SETTINGS_PATH = path.join(ROOT, 'settings.json');

const DEFAULTS = {
  server: '',
  streams: false,
  only: '',
  out: './dump',
};

export async function loadSettings() {
  try {
    const raw = await fsp.readFile(SETTINGS_PATH, 'utf8');
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export async function saveSettings(patch) {
  const next = { ...(await loadSettings()), ...patch };
  try {
    await fsp.writeFile(SETTINGS_PATH, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  } catch {
    /* not fatal: the wizard just won't remember anything */
  }
  return next;
}
