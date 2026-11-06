// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Reader for the RPF2 packfiles FXServer builds for client download.
//
// Layout produced by fi::PackfileBuilder (citizen-server-impl/ResourceFilesComponent.cpp):
//
//   0x0000  u32 magic        0x32465052 ("RPF2")
//   0x0004  u32 tocSize      byte offset where file data starts (>= 2048)
//   0x0008  u32 numEntries   total entry count, root included
//   0x000c  u32 zero
//   0x0010  u32 zero         non-zero would mean an encrypted archive
//   0x0800  entry[numEntries] (16 bytes each), then the name table
//
// Each entry:
//   0x00  u32 nameOffset     offset into the name table
//   0x04  u32 length         file size, or child count for directories
//   0x08  u32 data           bit31 = isDirectory; remaining bits are either the
//                            absolute file offset (file) or the index of the first
//                            child entry (directory)
//   0x0c  u32 flags          file size again, or child count
//
// Entry 0 is the root directory; its children are stored contiguously.
import fsp from 'node:fs/promises';

export const RPF2_MAGIC = 0x32465052;
const HEADER_SIZE = 20;
const TOC_OFFSET = 2048;
const ENTRY_SIZE = 16;
const MAX_ENTRIES = 2_000_000;
const DIR_BIT = 0x80000000;

export class Rpf2Archive {
  constructor({ path, fileSize, header, entries, nameBuffer, handle }) {
    this.path = path;
    this.fileSize = fileSize;
    this.header = header;
    this.entries = entries;
    this.nameBuffer = nameBuffer;
    this.handle = handle;
  }

  /** Open and parse an RPF2 archive. Throws with a readable reason on failure. */
  static async open(filePath) {
    const handle = await fsp.open(filePath, 'r');
    try {
      const stat = await handle.stat();
      const fileSize = stat.size;

      if (fileSize < TOC_OFFSET + ENTRY_SIZE) {
        throw new Error(`file is too small to be an RPF2 archive (${fileSize} bytes)`);
      }

      const headerBuffer = Buffer.alloc(HEADER_SIZE);
      const { bytesRead } = await handle.read(headerBuffer, 0, HEADER_SIZE, 0);
      if (bytesRead < HEADER_SIZE) throw new Error('truncated RPF2 header');

      const header = {
        magic: headerBuffer.readUInt32LE(0),
        tocSize: headerBuffer.readUInt32LE(4),
        numEntries: headerBuffer.readUInt32LE(8),
        unknownA: headerBuffer.readUInt32LE(12),
        cryptoFlag: headerBuffer.readUInt32LE(16),
      };

      if (header.magic !== RPF2_MAGIC) {
        throw new Error(
          `bad magic 0x${header.magic.toString(16).padStart(8, '0')} (expected 0x32465052 / "RPF2")`,
        );
      }
      if (header.cryptoFlag !== 0) {
        throw new Error(`archive is encrypted (cryptoFlag=${header.cryptoFlag}); unsupported`);
      }
      if (header.numEntries < 1 || header.numEntries > MAX_ENTRIES) {
        throw new Error(`implausible entry count: ${header.numEntries}`);
      }

      const entryBytes = header.numEntries * ENTRY_SIZE;
      if (TOC_OFFSET + entryBytes > fileSize) {
        throw new Error(`entry table (${header.numEntries}) overruns file size (${fileSize})`);
      }

      // tocSize covers header + entries + name table + alignment padding, so the
      // name table runs from right after the entries up to tocSize.
      let tocLength;
      if (header.tocSize >= TOC_OFFSET + entryBytes) {
        tocLength = Math.min(header.tocSize - TOC_OFFSET, fileSize - TOC_OFFSET);
      } else {
        // Some writers leave tocSize at zero; fall back to a bounded read.
        tocLength = Math.min(fileSize - TOC_OFFSET, 32 * 1024 * 1024);
      }

      const tocBuffer = Buffer.alloc(tocLength);
      const read = await handle.read(tocBuffer, 0, tocLength, TOC_OFFSET);
      const usable = read.bytesRead;

      const entries = [];
      for (let i = 0; i < header.numEntries; i++) {
        const at = i * ENTRY_SIZE;
        if (at + ENTRY_SIZE > usable) break;

        const nameOffset = tocBuffer.readUInt32LE(at);
        const length = tocBuffer.readUInt32LE(at + 4);
        const dataRaw = tocBuffer.readUInt32LE(at + 8);
        const flags = tocBuffer.readUInt32LE(at + 12);
        const isDirectory = (dataRaw & DIR_BIT) !== 0;
        const dataValue = dataRaw & 0x7fffffff;

        entries.push({
          index: i,
          nameOffset,
          length,
          flags,
          isDirectory,
          // Directories store the index of their first child here; files store
          // an absolute offset into the archive.
          firstChildIndex: isDirectory ? dataValue : 0,
          offset: isDirectory ? 0 : dataValue,
          name: '',
        });
      }

      const nameStart = header.numEntries * ENTRY_SIZE;
      const nameBuffer = tocBuffer.subarray(nameStart);

      for (const entry of entries) {
        entry.name = readName(nameBuffer, entry.nameOffset);
      }

      return new Rpf2Archive({
        path: filePath,
        fileSize,
        header,
        entries,
        nameBuffer,
        handle,
      });
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
  }

  get entryCount() {
    return this.entries.length;
  }

  /** Direct children of a directory entry, clamped to the table. */
  children(dirEntry) {
    if (!dirEntry || !dirEntry.isDirectory) return [];
    const start = dirEntry.firstChildIndex;
    const count = Math.min(dirEntry.length, this.entries.length - start);
    if (start < 0 || count <= 0) return [];
    return this.entries.slice(start, start + count);
  }

  /** Every file in the archive, paths relative to the archive root. */
  listFiles() {
    const files = [];
    const root = this.entries[0];
    if (!root) return files;

    const visited = new Set([0]);
    const stack = [{ dir: root, base: '', depth: 0 }];

    while (stack.length > 0) {
      const { dir, base, depth } = stack.pop();

      if (depth > 64) {
        throw new Error(`directory nesting too deep (>64) at "${base || '/'}"`);
      }

      for (const entry of this.children(dir)) {
        const name = entry.name.replace(/^\/+/, '');
        if (!name) continue;

        const relative = base ? `${base}/${name}` : name;

        if (entry.isDirectory) {
          if (visited.has(entry.index)) continue; // cycle guard on malformed archives
          visited.add(entry.index);
          stack.push({ dir: entry, base: relative, depth: depth + 1 });
        } else {
          files.push({
            path: relative,
            size: entry.length,
            offset: entry.offset,
            index: entry.index,
          });
        }
      }
    }

    files.sort((a, b) => a.path.localeCompare(b.path));
    return files;
  }

  /** True when the file's [offset, offset+size) lies inside the archive. */
  isEntryInBounds(entry) {
    const { offset, size } = normalizeEntry(entry);
    return offset >= 0 && size >= 0 && offset + size <= this.fileSize;
  }

  /** Write one file entry to disk. Accepts either an entry or a listFiles() record. */
  async writeEntryTo(entry, destination, { chunkSize = 4 * 1024 * 1024 } = {}) {
    const { offset, size } = normalizeEntry(entry);

    if (!this.isEntryInBounds(entry)) {
      throw new Error(
        `entry out of bounds (offset=${offset} size=${size} file=${this.fileSize})`,
      );
    }

    const target = await fsp.open(destination, 'w');
    try {
      if (size === 0) return 0;

      const buffer = Buffer.allocUnsafe(Math.min(chunkSize, size));
      let position = offset;
      let remaining = size;

      while (remaining > 0) {
        const want = Math.min(buffer.length, remaining);
        const { bytesRead } = await this.handle.read(buffer, 0, want, position);
        if (bytesRead <= 0) throw new Error('unexpected end of archive while reading entry');

        await target.write(buffer.subarray(0, bytesRead), 0, bytesRead);
        position += bytesRead;
        remaining -= bytesRead;
      }

      return size;
    } finally {
      await target.close();
    }
  }

  async close() {
    if (this.handle) {
      const handle = this.handle;
      this.handle = null;
      await handle.close().catch(() => {});
    }
  }
}

function readName(nameBuffer, offset) {
  if (!nameBuffer || offset < 0 || offset >= nameBuffer.length) return '';

  let end = offset;
  while (end < nameBuffer.length && nameBuffer[end] !== 0) end += 1;

  return nameBuffer.toString('utf8', offset, end);
}

/** listFiles() records carry `size`; raw TOC entries carry `length`. */
function normalizeEntry(entry) {
  const offset = Number(entry?.offset ?? 0);
  const size = Number(entry?.size ?? entry?.length ?? 0);
  return { offset, size };
}
