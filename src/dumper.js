// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Orchestration: turn a getConfiguration payload into files on disk.
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  decryptFile,
  fileStartsWithRpf2,
  hexDump,
  parseResourceUri,
} from './crypto.js';
import {
  bruteForceKeyDecode,
  decryptFileWithProfile,
  probeDecryption,
} from './probe.js';
import { Rpf2Archive } from './rpf2.js';
import { ensureDir, humanBytes, log, safeName, safeRelPath, sha1File } from './util.js';

const STRICT_MODES = ['chacha20', 'chacha20-rfc7539'];
const PROBE_HEAD_BYTES = 512;

/** A payload we could not turn into plaintext; carries enough detail to diagnose. */
export class PayloadError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'PayloadError';
    Object.assign(this, details);
  }
}

/**
 * Recover the plaintext of a served payload.
 *
 * Order of evidence, cheapest first:
 *   1. the served bytes already hash to the advertised value  -> plaintext
 *   2. the served bytes already start with an RPF2 header    -> plaintext
 *   3. a short probe finds a key/cipher profile that yields an RPF2 header
 *   4. (stream files only) the documented layouts, verified by hash
 *
 * FXServer advertises the SHA-1 of the *plaintext*, so a hash match is proof. When
 * the server runs a protection layer the scheme may differ from the documented one;
 * the probe in src/probe.js covers the layouts seen in practice.
 */
export async function resolveContent({
  tmpPath,
  advertisedHash,
  uri,
  fileName,
  workDir,
  wantContainer = true,
}) {
  const notes = [];
  const created = [];
  const servedSha1 = await sha1File(tmpPath);
  const servedSize = (await fsp.stat(tmpPath)).size;
  const verifiedPlain = Boolean(advertisedHash) && servedSha1 === advertisedHash;

  if (verifiedPlain) {
    return {
      path: tmpPath,
      verified: true,
      mode: 'plaintext',
      notes,
      sha1: servedSha1,
      size: servedSize,
      created,
    };
  }

  const looksPlainRpf = await fileStartsWithRpf2(tmpPath);

  // A structural match beats the advertised hash: if the bytes already are a
  // packfile there is nothing to decrypt, even if the hash disagrees.
  if (looksPlainRpf) {
    notes.push(
      advertisedHash
        ? `hash mismatch (served ${servedSha1}, expected ${advertisedHash}) but payload is a plain RPF2`
        : 'no advertised hash; payload is a plain RPF2',
    );
    return {
      path: tmpPath,
      verified: false,
      mode: 'plaintext',
      notes,
      sha1: servedSha1,
      size: servedSize,
      created,
    };
  }

  const servedHead = await readHead(tmpPath, 16);
  const servedHeadHex = hexDump(servedHead);

  if (!uri) {
    throw new PayloadError(
      `payload is not a plain RPF2 and the server sent no decryption key (uri); first bytes: ${servedHeadHex}`,
      { servedSha1, servedSize, advertisedHash, notes },
    );
  }

  let keyMaterial;
  try {
    keyMaterial = parseResourceUri(uri);
  } catch (error) {
    throw new PayloadError(`could not decode resource uri: ${error.message}`, {
      servedSha1,
      servedSize,
      advertisedHash,
      uri,
      notes,
    });
  }

  notes.push(
    `uri v${keyMaterial.version}: key ${keyMaterial.key.length}B, iv ${keyMaterial.iv.length}B`,
  );
  if (keyMaterial.version !== 3) {
    notes.push(`unexpected uri version ${keyMaterial.version}; probing anyway`);
  }

  let fallback = null;
  let probe = { hits: [], results: [] };
  let attempts = 0;

  const accept = (candidatePath, plainSha1, mode) => ({
    path: candidatePath,
    verified: true,
    mode,
    notes,
    sha1: plainSha1,
    size: 0,
    created,
  });

  if (wantContainer) {
    probe = probeDecryption({
      head: await readHead(tmpPath, PROBE_HEAD_BYTES),
      keyMaterial,
      fileName,
    });
    attempts = probe.results.length;

    notes.push(
      probe.hits.length > 0
        ? `probe matched ${probe.hits.length} profile(s): ${probe.hits.map((hit) => hit.id).join(' | ')}`
        : `probe tried ${probe.results.length} combination(s), none produced an RPF2 header`,
    );

    for (const hit of probe.hits.slice(0, 6)) {
      const candidatePath = path.join(workDir, `${crypto.randomUUID()}.dec`);
      created.push(candidatePath);

      const plainSha1 = await decryptFileWithProfile(tmpPath, candidatePath, hit);
      const size = (await fsp.stat(candidatePath)).size;

      if (advertisedHash && plainSha1 === advertisedHash) {
        notes.push(`${hit.id}: sha1 verified`);
        return { ...accept(candidatePath, plainSha1, hit.label ?? hit.id), size };
      }

      if (await fileStartsWithRpf2(candidatePath)) {
        notes.push(`${hit.id}: valid RPF2 but sha1 differs (got ${plainSha1})`);
        fallback ??= {
          path: candidatePath,
          verified: false,
          mode: `${hit.id} (unverified)`,
          notes,
          sha1: plainSha1,
          size,
          created,
        };
      } else {
        notes.push(`${hit.id}: not an RPF2 after decryption`);
      }
    }
  } else {
    // Stream files have no magic to probe for, so verify by hash over the
    // documented layouts instead.
    const nameCandidates = fileName === 'resource.rpf' ? [fileName] : [fileName, 'resource.rpf'];

    for (const mode of STRICT_MODES) {
      for (const name of nameCandidates) {
        attempts += 1;
        const candidatePath = path.join(workDir, `${crypto.randomUUID()}.dec`);
        created.push(candidatePath);

        let plainSha1;
        try {
          plainSha1 = await decryptFile(tmpPath, candidatePath, {
            masterKey: keyMaterial.key,
            iv: keyMaterial.iv,
            fileName: name,
            mode,
          });
        } catch (error) {
          notes.push(`${mode}/${name}: decrypt failed (${error.message})`);
          continue;
        }

        const size = (await fsp.stat(candidatePath)).size;

        if (advertisedHash && plainSha1 === advertisedHash) {
          notes.push(`${mode}/${name}: sha1 verified`);
          return { ...accept(candidatePath, plainSha1, `${mode}/${name}`), size };
        }

        notes.push(`${mode}/${name}: sha1 mismatch (got ${plainSha1})`);
      }
    }
  }

  if (fallback) return fallback;

  throw new PayloadError(
    `could not recover plaintext: ${attempts} decryption combination(s) tried, none verified. ` +
      `This server encrypts resources with a scheme this build does not recognise. ` +
      `first bytes: ${servedHeadHex}. Re-run with --diagnose to save a sample.`,
    { servedSha1, servedSize, advertisedHash, uri, probe: probe.results, notes },
  );
}

async function readHead(filePath, length) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

/* --------------------------------------------------------------- extraction */

async function extractArchive(archive, destinationDir, stats) {
  const entries = archive.listFiles();
  if (entries.length === 0) {
    log.warn(`archive contains no files (${entries.length} entries scanned)`);
    return;
  }

  for (const entry of entries) {
    const relative = safeRelPath(entry.path);
    if (!relative) {
      log.detail(`skipping unsafe path: ${JSON.stringify(entry.path)}`);
      stats.skipped += 1;
      continue;
    }

    if (stats.written.has(relative)) {
      log.detail(`duplicate path, overwriting: ${relative}`);
    }

    const target = path.join(destinationDir, relative);
    await ensureDir(path.dirname(target));

    try {
      await archive.writeEntryTo(entry, target);
      stats.written.add(relative);
      stats.files += 1;
      stats.bytes += entry.size;
      if (entry.size > 1024 * 1024) {
        log.detail(`  ${relative} (${humanBytes(entry.size)})`);
      }
    } catch (error) {
      stats.failed += 1;
      stats.errors.push(`${relative}: ${error.message}`);
      log.warn(`${relative}: ${error.message}`);
    }
  }
}

/* ------------------------------------------------------------------- runner */

export async function mapWithConcurrency(items, limit, worker, signal) {
  const results = new Array(items.length);
  let nextIndex = 0;

  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      if (signal?.aborted) return;
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  });

  await Promise.all(runners);
  return results;
}

export function filterResources(resources, { only = [], exclude = [] } = {}) {
  const onlySet = new Set(only.map((s) => s.toLowerCase()));
  const excludeSet = new Set(exclude.map((s) => s.toLowerCase()));

  return resources.filter((resource) => {
    const name = String(resource?.name ?? '');
    if (!name) return false;
    const lower = name.toLowerCase();
    if (onlySet.size > 0 && !onlySet.has(lower)) return false;
    if (excludeSet.has(lower)) return false;
    return true;
  });
}

/**
 * Dump a single resource: every `.rpf` in `files` is unpacked, loose files are
 * written as-is, and stream assets are fetched when enabled.
 */
export async function dumpResource({
  client,
  resource,
  outDir,
  tmpDir,
  options,
  signal,
  defaultFileServer,
  progress = () => {},
}) {
  const name = String(resource.name);
  const resourceDir = path.join(outDir, safeName(name, 'resource'));
  // Per-resource override (fileserver_add) wins over the server-wide template.
  const fileServer = resource.fileServer ?? defaultFileServer;
  const result = {
    name,
    ok: false,
    skipped: false,
    archives: [],
    streams: { total: 0, downloaded: 0, verified: 0, failed: 0, bytes: 0 },
    files: 0,
    bytes: 0,
    errors: [],
    notes: [],
  };

  const files = resource.files && typeof resource.files === 'object' ? Object.entries(resource.files) : [];
  const streamFiles =
    resource.streamFiles && typeof resource.streamFiles === 'object'
      ? Object.entries(resource.streamFiles)
      : [];

  if (files.length === 0 && streamFiles.length === 0) {
    result.skipped = true;
    result.notes.push('server listed no downloadable files for this resource');
    return result;
  }

  if (files.length > 0) await ensureDir(resourceDir);

  try {
    for (const [fileName, hash] of files) {
      if (signal?.aborted) throw new Error('aborted');

      const tmpPath = path.join(tmpDir, `${crypto.randomUUID()}.bin`);
      progress({ phase: 'download', fileName });

      const download = await client.downloadFile({
        resourceName: name,
        fileName,
        hash,
        destination: tmpPath,
        fileServer,
      });

      if (download.truncated) {
        result.notes.push(`${fileName}: content-length mismatch (${download.size} bytes received)`);
      }

      let resolved;
      try {
        resolved = await resolveContent({
          tmpPath,
          advertisedHash: hash,
          uri: resource.uri,
          fileName,
          workDir: tmpDir,
          wantContainer: fileName.toLowerCase().endsWith('.rpf'),
        });
      } catch (error) {
        if (options.diagnose && error instanceof PayloadError) {
          // Diagnose mode tries harder before giving up: brute-force the key-blob
          // parameters, and if that fails, keep a sample for offline analysis.
          const recovered = await attemptRecovery({
            tmpPath,
            workDir: tmpDir,
            fileName,
            advertisedHash: hash,
            uri: resource.uri,
          });

          if (recovered) {
            resolved = recovered;
            result.notes.push(`${fileName}: recovered by brute force (${recovered.mode})`);
          } else {
            const saved = await saveDiagnostics({
              outDir,
              resource: name,
              fileName,
              tmpPath,
              error,
            });
            if (saved) result.notes.push(`diagnostics written to ${saved}`);
            throw error;
          }
        } else {
          throw error;
        }
      }

      result.notes.push(
        ...resolved.notes.map((note) => `${fileName}: ${note}`),
        `${fileName}: served as ${resolved.mode}${resolved.verified ? ' [verified]' : ' [UNVERIFIED]'}`,
      );

      const isRpf = await fileStartsWithRpf2(resolved.path);

      if (isRpf) {
        if (options.keepArchive) {
          await fsp.copyFile(resolved.path, path.join(resourceDir, safeName(fileName, 'archive.rpf')));
        }

        const archive = await Rpf2Archive.open(resolved.path);
        try {
          const stats = { files: 0, bytes: 0, skipped: 0, failed: 0, errors: [], written: new Set() };
          await extractArchive(archive, resourceDir, stats);

          result.files += stats.files;
          result.bytes += stats.bytes;
          result.errors.push(...stats.errors);
          result.archives.push({
            file: fileName,
            hash: hash ?? null,
            size: resolved.size,
            verified: resolved.verified,
            mode: resolved.mode,
            entries: archive.entryCount,
            extracted: stats.files,
            failed: stats.failed,
          });
        } finally {
          await archive.close();
        }
      } else {
        // Loose file (not an RPF2 container): keep it verbatim.
        const relative = safeRelPath(fileName, { allowDirs: false }) ?? 'file.bin';
        const target = path.join(resourceDir, relative);
        await ensureDir(path.dirname(target));
        await fsp.copyFile(resolved.path, target);
        result.files += 1;
        result.bytes += resolved.size;
        result.archives.push({
          file: fileName,
          hash: hash ?? null,
          size: resolved.size,
          verified: resolved.verified,
          mode: resolved.mode,
          entries: 0,
          extracted: 1,
          failed: 0,
        });
      }

      await cleanupPaths([tmpPath, ...resolved.created.filter((p) => p !== resolved.path)]);
    }

    if (options.streams && streamFiles.length > 0) {
      await dumpStreams({
        client,
        resource,
        resourceDir,
        tmpDir,
        options,
        signal,
        result,
        progress,
        fileServer,
      });
    }

    result.ok = result.errors.length === 0 || result.files > 0;
  } catch (error) {
    if (signal?.aborted) {
      result.errors.push('aborted');
    } else {
      result.errors.push(error.message);
    }
    result.ok = false;
  }

  return result;
}

async function dumpStreams({
  client,
  resource,
  resourceDir,
  tmpDir,
  options,
  signal,
  result,
  progress,
  fileServer,
}) {
  const entries = Object.entries(resource.streamFiles);
  result.streams.total = entries.length;

  const mode = options.streamDecrypt; // 'auto' | 'always' | 'never'
  const targetRoot = path.join(resourceDir, 'stream');

  for (const [rawName, meta] of entries) {
    if (signal?.aborted) break;

    const fileName = String(rawName);
    const advertisedHash = meta && typeof meta === 'object' ? meta.hash : undefined;
    // Streaming-list keys are bare names, but tolerate a "stream/" prefix without
    // producing stream/stream/... on disk. The HMAC still uses the original name.
    const streamRelative = fileName.replace(/^\/?stream\//i, '');
    const relative = safeRelPath(streamRelative) ?? safeName(fileName, 'stream.bin');
    const target = path.join(targetRoot, relative);
    const tmpPath = path.join(tmpDir, `${crypto.randomUUID()}.stream`);

    progress({ phase: 'stream', fileName });

    try {
      const download = await client.downloadFile({
        resourceName: resource.name,
        fileName,
        hash: advertisedHash,
        destination: tmpPath,
        fileServer,
      });

      let source = tmpPath;
      let temporary = [];
      let verified = Boolean(advertisedHash) && download.sha1 === advertisedHash;
      let reason = verified ? '' : 'served bytes did not match the advertised hash';

      if (!verified && mode !== 'never' && resource.uri) {
        try {
          const resolved = await resolveContent({
            tmpPath,
            advertisedHash,
            uri: resource.uri,
            fileName,
            workDir: tmpDir,
            wantContainer: false,
          });
          source = resolved.path;
          verified = resolved.verified;
          temporary = resolved.created;
          reason = resolved.verified ? '' : 'decryption produced bytes that did not verify';
        } catch (error) {
          reason = error.message;
        }
      }

      // In "auto" mode an unverified stream is withheld rather than written as
      // plausible-looking garbage; "always"/"never" are explicit overrides.
      const mayWrite = verified || mode === 'always' || mode === 'never';

      if (!mayWrite) {
        result.streams.failed += 1;
        result.errors.push(
          `stream ${fileName}: not written (${reason}); use --stream-decrypt always to force`,
        );
        await cleanupPaths([tmpPath, ...temporary]);
        continue;
      }

      await ensureDir(path.dirname(target));
      await fsp.copyFile(source, target);

      result.streams.downloaded += 1;
      result.streams.bytes += download.size;

      if (verified) {
        result.streams.verified += 1;
      } else {
        result.notes.push(`stream ${fileName}: written unverified (${reason || mode})`);
      }

      await cleanupPaths([tmpPath, ...temporary.filter((p) => p !== source)]);
    } catch (error) {
      result.streams.failed += 1;
      result.errors.push(`stream ${fileName}: ${error.message}`);
    }
  }
}

const DIAGNOSTIC_HEAD_BYTES = 1024 * 1024;

/**
 * Last-ditch recovery for a payload the normal path could not open: search the
 * key-blob parameter space, then decrypt the whole file with any candidate whose
 * first bytes look like a packfile.
 */
async function attemptRecovery({ tmpPath, workDir, fileName, advertisedHash, uri }) {
  if (!uri) return null;

  const head = await readHead(tmpPath, 64);
  const { hits } = bruteForceKeyDecode({ head, uri });

  if (hits.length > 0) {
    log.detail(`brute force found ${hits.length} candidate key(s): ${hits.map((h) => h.id).join(' | ')}`);
  }

  for (const hit of hits.slice(0, 4)) {
    const candidatePath = path.join(workDir, `${crypto.randomUUID()}.dec`);
    const plainSha1 = await decryptFileWithProfile(tmpPath, candidatePath, hit);
    const size = (await fsp.stat(candidatePath)).size;

    if (advertisedHash && plainSha1 === advertisedHash) {
      return {
        path: candidatePath,
        verified: true,
        mode: hit.label,
        notes: [],
        sha1: plainSha1,
        size,
        created: [candidatePath],
      };
    }

    if (await fileStartsWithRpf2(candidatePath)) {
      return {
        path: candidatePath,
        verified: false,
        mode: `${hit.label} (unverified)`,
        notes: [],
        sha1: plainSha1,
        size,
        created: [candidatePath],
      };
    }
  }

  return null;
}

/**
 * Persist a sample of an undecryptable payload plus everything needed to work out
 * its scheme offline: the key blob, the hashes, and the probe matrix output.
 */
async function saveDiagnostics({ outDir, resource, fileName, tmpPath, error }) {
  const target = path.join(outDir, '_diagnostics', safeName(resource, 'resource'));
  await ensureDir(target);

  const stem = safeName(fileName, 'payload');
  const head = await readHead(tmpPath, DIAGNOSTIC_HEAD_BYTES);

  const meta = {
    tool: 'fivem-dumper',
    createdAt: new Date().toISOString(),
    resource,
    fileName,
    uri: error.uri ?? null,
    advertisedHash: error.advertisedHash ?? null,
    servedSha1: error.servedSha1 ?? null,
    servedSize: error.servedSize ?? null,
    error: error.message,
    notes: error.notes ?? [],
    probe: error.probe ?? [],
    savedHeadBytes: head.length,
  };

  await Promise.all([
    fsp.writeFile(
      path.join(target, `${stem}.meta.json`),
      `${JSON.stringify(meta, null, 2)}\n`,
      'utf8',
    ),
    fsp.writeFile(path.join(target, `${stem}.served.bin`), head),
  ]);

  return target;
}

async function cleanupPaths(paths) {
  await Promise.all(
    paths.map((p) => fsp.rm(p, { force: true }).catch(() => {})),
  );
}
