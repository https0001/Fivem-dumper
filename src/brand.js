// Single source of truth for the author identity and the community link.
// Everything user-facing reads from here so the credit stays identical
// in the banner, the help text, the manifest and the wizard.

export const AUTHOR = 'Mohammed';
export const DISCORD = 'https://discord.gg/6G6m74Ynbw';
export const COMMUNITY = 'http';
export const COPYRIGHT = `© ${new Date().getFullYear()} ${AUTHOR} — all rights reserved`;
export const DISCLAIMER =
  'For educational purposes only — the author is not responsible for any misuse.';

export const creditLine = () => `by ${AUTHOR} · ${DISCORD}`;
