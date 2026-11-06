// fivem-dumper · © 2026 Mohammed · https://discord.gg/6G6m74Ynbw
// Decoder for the resource key blobs some servers hand out with getConfiguration.
//
// Vanilla FXServer emits no `uri` field at all. When one is present it can be:
//
//   v3#<base64>                     (obfuscated raw key material)
//   ci://<resource>/v3#<base64>     (MessagePack: [["<profile>", "<cipher>", key, iv]])
//
// The MessagePack form is produced by third-party resource-protection layers, not
// by FXServer itself, so treat it as best-effort: we can recover the key and iv the
// server handed to every client, but the cipher parameters remain the vendor's.
const MAX_STRING = 4096;

function decodeMsgpack(buffer) {
  let offset = 0;

  const need = (count) => {
    if (offset + count > buffer.length) throw new Error('truncated msgpack value');
  };

  const readLength = (spec) => {
    if (spec === 'u8') {
      need(1);
      return buffer[offset++];
    }
    if (spec === 'u16') {
      need(2);
      const value = buffer.readUInt16BE(offset);
      offset += 2;
      return value;
    }
    need(4);
    const value = buffer.readUInt32BE(offset);
    offset += 4;
    return value;
  };

  const readBinary = (spec) => {
    const length = readLength(spec);
    if (length > buffer.length) throw new Error('implausible msgpack length');
    need(length);
    const value = Buffer.from(buffer.subarray(offset, offset + length));
    offset += length;
    return value;
  };

  const readString = (spec) => {
    const length = readLength(spec);
    if (length > MAX_STRING) throw new Error('implausible msgpack string length');
    need(length);
    const value = buffer.toString('utf8', offset, offset + length);
    offset += length;
    return value;
  };

  const value = () => {
    need(1);
    const marker = buffer[offset++];

    if (marker >= 0x00 && marker <= 0x7f) return marker; // positive fixint
    if (marker >= 0x80 && marker <= 0x8f) {
      // fixmap: keys are not needed by any known blob, but decode for safety
      const size = marker & 0x0f;
      const map = {};
      for (let i = 0; i < size; i++) {
        const key = value();
        map[String(key)] = value();
      }
      return map;
    }
    if (marker >= 0x90 && marker <= 0x9f) {
      const size = marker & 0x0f;
      const array = [];
      for (let i = 0; i < size; i++) array.push(value());
      return array;
    }
    if (marker >= 0xa0 && marker <= 0xbf) {
      const length = marker & 0x1f;
      need(length);
      const text = buffer.toString('utf8', offset, offset + length);
      offset += length;
      return text;
    }
    if (marker >= 0xe0) return marker - 0x100; // negative fixint

    switch (marker) {
      case 0xc0:
        return null;
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xc4:
        return readBinary('u8');
      case 0xc5:
        return readBinary('u16');
      case 0xc6:
        return readBinary('u32');
      case 0xd9:
        return readString('u8');
      case 0xda:
        return readString('u16');
      case 0xdb:
        return readString('u32');
      case 0xdc: {
        const size = readLength('u16');
        const array = [];
        for (let i = 0; i < size; i++) array.push(value());
        return array;
      }
      case 0xdd: {
        const size = readLength('u32');
        const array = [];
        for (let i = 0; i < size; i++) array.push(value());
        return array;
      }
      case 0xcc:
        return readLength('u8');
      case 0xcd:
        return readLength('u16');
      case 0xce:
        return readLength('u32');
      default:
        throw new Error(`unsupported msgpack marker 0x${marker.toString(16)}`);
    }
  };

  const result = value();
  return { result, consumed: offset };
}

/**
 * Try to read a MessagePack key blob: [[profile, cipher, key, iv]].
 * @returns {{profile: string, algorithm: string, key: Buffer, iv: Buffer}|null}
 */
export function parseKeyBlob(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 8) return null;

  let decoded;
  try {
    decoded = decodeMsgpack(raw);
  } catch {
    return null;
  }

  let fields = decoded.result;
  if (Array.isArray(fields) && fields.length === 1 && Array.isArray(fields[0])) {
    fields = fields[0];
  }

  if (!Array.isArray(fields) || fields.length < 4) return null;

  const [profile, algorithm, key, iv] = fields;
  if (typeof profile !== 'string' || typeof algorithm !== 'string') return null;
  if (!Buffer.isBuffer(key) || key.length < 16) return null;
  if (!Buffer.isBuffer(iv) || iv.length < 8) return null;

  return { profile, algorithm, key, iv };
}
