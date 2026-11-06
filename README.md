# fivem-dumper

**by Mohammed** — https://discord.gg/6G6m74Ynbw

> **© 2026 Mohammed — all rights reserved.**
> Free to use and share unchanged. Keep this credit block and the Discord link
> intact: no resale, no rebrand, no removing the author. Full terms in [LICENSE](LICENSE).
>
> **FOR EDUCATIONAL PURPOSES ONLY.** Use it on servers you own, administrate, or
> have written permission to test. The author is **not responsible for any misuse**
> or for any damage caused by this tool or by how it is used.
>
> Project home / support / updates: **http** — https://discord.gg/6G6m74Ynbw

Pulls the **client resource package** off a live FiveM/FXServer server and unpacks it to disk.

---

## Quick start (no commands)

1. Join the server in **FiveM** and keep it open.
2. **Double-click** `start.cmd`.
3. Answer three questions:
   - server address — an IP (`203.0.113.7:30120`), a URL, or a `cfx.re/join/p39bpy` link
   - include stream assets (vehicles/maps/clothing)? `y` or `n`
   - a single resource name, or blank for everything

That's it. Files land in `dump\<ip>_<port>\` and the tool offers to open the folder.

Your last answers are remembered in `settings.json`, so the next run is just Enter.

> The advanced command-line interface is documented below in **Usage** — entirely optional.

---

It talks to the server the same way the game client does — no injection, no patching,
no game process touched — and it verifies every byte it writes against the SHA-1 the
server publishes, so you can tell a clean extraction from a corrupt one.

```
node src/cli.js --server 203.0.113.7:30120 --out ./dump
```

---

## Read this first: what it can and cannot get

FXServer only ever sends clients the *client-side* part of a resource. That is what this
tool retrieves:

| Retrieved | Not retrieved |
| --- | --- |
| `fxmanifest.lua` / `__resource.lua` | `server_script` files |
| `client_script` files | anything only read server-side (`server.lua`, SQL, configs used only on the server) |
| `shared_script` files | resources marked `server_only` (never sent to clients) |
| every `files` entry (NUI, JSON, data files) | escrowed / FXAP-protected assets |
| `map` entries | |
| stream assets (`.ytd`, `.yft`, `.ydr`, …) with `--streams` | |

So: you get exactly what a cheater would get by joining the server — nothing more.
If a resource's logic lives in `server_script`, that file is **not** on this side of the wire
and no client-side technique can produce it.

Use it on servers you own or administrate, or where you have the owner's permission.
Pulling assets off other people's servers to reuse or resell them breaks the Cfx.re terms
and is what the "no asset dumping" rules exist for.

> **This tool is published for educational and research purposes only.**
> You are responsible for how you use it. The author (Mohammed) is not responsible
> for any misuse, for any damage, or for any consequence of running this software.

---

## Requirements

- Node.js **20+**
- No npm dependencies — everything is `node:` built-ins

## Usage

```bash
# 1. connect to the server in the FiveM client and stay connected
# 2. then, from the same machine:

node src/cli.js --server 203.0.113.7:30120

# a bare host gets http:// and :30120 automatically
node src/cli.js -s play.example.com

# a cfx.re join link works too (resolved through the server-list API)
node src/cli.js -s cfx.re/join/p39bpy

# ...and so does the fivem:// link your browser hands to the client
node src/cli.js -s "fivem://connect/203.0.113.7:30120"

# just look around, download nothing
node src/cli.js -s 203.0.113.7:30120 --dry-run

# only two resources, with their stream assets, 6 at a time
node src/cli.js -s 203.0.113.7:30120 --only mymap,myvehicle --streams -c 6

# public server info only — works without joining
node src/cli.js -s 203.0.113.7:30120 --info
```

### Accepted server address formats

| Format | Example |
| --- | --- |
| IP or host, port optional | `203.0.113.7:30120`, `play.example.com` |
| URL | `http://203.0.113.7:30120`, `https://host` |
| Cfx.re join link | `cfx.re/join/p39bpy`, `https://cfx.re/join/p39bpy` |
| FiveM deep link | `fivem://connect/203.0.113.7:30120` |
| Bare join code | `p39bpy` |

Join links are not HTTP redirects — the tool resolves the code through
`frontend.cfx-services.net/api/servers/single/<code>` and uses its
`Data.connectEndPoints` entry, so `--info` on a join link also prints the resolved
IP before doing anything else.


### Why must I join the server first?

`POST /client` with `method=getConfiguration` is the endpoint that lists downloadable files,
and FXServer only answers it for a client it can see. From
`GetConfigurationMethod.cpp`:

```cpp
auto token = request->GetHeader("X-CitizenFX-Token");
if (!token.empty()) client = clientRegistry->GetClientByConnectionToken(token);
if (!client)        client = clientRegistry->GetClientByTcpEndPoint(ip);
if (!client)                    return sendError("Not a valid client.");
if (!client->GetData("passedValidation")) return sendError("Client is still connecting.");
```

Two ways to satisfy that:

1. **Be a connected client** (normal route) — join with the FiveM client and keep it
   connected. The tool runs from the same machine, so the source IP matches.
2. **Pass a token** — `--token <connection-token>` (or `CITIZENFX_TOKEN` env var) if you
   have one, e.g. from your own server's debug tooling.

Nothing else is authenticated: `/files/<resource>/<file>` serves the payload without a
token, and `/info.json` is public.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-s, --server <addr>` | — | IP, URL, `cfx.re/join/<code>`, or `fivem://` link |
| `-o, --out <dir>` | `./dump` | Output root; files land in `<out>/<host>_<port>/` |
| `--only <a,b>` | all | Only these resources (also sent server-side as a filter) |
| `--exclude <a,b>` | none | Skip these |
| `--streams` | off | Also fetch stream assets — usually the bulk of the size |
| `--stream-decrypt <m>` | `auto` | `auto` (decrypt only when the hash verifies), `always`, `never` |
| `-c, --concurrency <n>` | `3` | Parallel resources |
| `--timeout <ms>` | `30000` | Idle socket timeout |
| `--token <token>` | env | `X-CitizenFX-Token` |
| `--insecure` | off | Skip TLS verification (self-signed hosts) |
| `--keep-archive` | off | Keep the downloaded `.rpf` next to its contents |
| `--diagnose` | off | Try harder on encrypted payloads, save a sample if still stuck |
| `--dry-run` | off | Print the plan, download nothing |
| `--info` | off | Print public `/info.json` only |
| `-v, --verbose` | off | Per-file detail, including why a payload was accepted |
| `-h, --help` | | Usage |

Exit codes: `0` success · `1` some resources failed · `2` fatal (bad args, not authorised, unreachable).

## Output

```
dump/203.0.113.7_30120/
├── manifest.json              # every resource, hash, verification result, error
├── mymap/
│   ├── fxmanifest.lua
│   ├── client/main.lua
│   ├── html/index.html
│   └── stream/veh.yft         # only with --streams
└── myvehicle/
    └── ...
```

`manifest.json` records, per resource, whether the archive hash verified, which decryption
mode was used, how many entries were extracted, and any errors — enough to audit a run
without re-downloading.

## How it works

1. `POST /client` (`method=getConfiguration`) → JSON describing each resource:
   `{ name, uri?, files: { "resource.rpf": "<sha1>" }, streamFiles: { name: { hash, size, ... } }, fileServer? }`
2. `GET <fileServer or /files>/<resource>/<file>?hash=<sha1>` streams the payload to a temp file
   while hashing it.
3. **Verify, then decrypt.** `files` hashes are the SHA-1 of the *plaintext* (see
   `ResourceFilesComponent.cpp`), which makes a perfect oracle: if the served bytes hash to
   the advertised value, no decryption is needed. If they do not, the tool uses the
   per-resource `uri` key blob to derive a ChaCha20 key and retries until the hash matches.
4. **Unpack.** `resource.rpf` is an RPF2 packfile — the same container FXServer's
   `fi::PackfileBuilder` writes. The reader follows that exact layout: 20-byte header, entry
   table at `0x800`, name table after it, absolute file offsets, bit 31 marking directories.

### The key blob

Two shapes are accepted:

**Legacy obfuscated form — `v3#<base64>`**

```
masterKey = xor( base64(uri)[19 .. len-8], 0x69 )[0 .. -2]
iv        = base64(uri)[len-8 ..]
fileKey   = HMAC-SHA256(masterKey, fileName)
plaintext = ChaCha20(fileKey, iv8, ciphertext)
```

**MessagePack form — `ci://<resource>/v3#<base64>`**

A newer wrapping used by several protection layers. The key bytes inside it are still
masked with the same `0x69` XOR:

```
base64 → MessagePack: [ [ "<profile>", "<cipher>", bin32(key ^ 0x69), bin8(iv) ] ]
masterKey = key ^ 0x69
```

The 19-byte header length of the legacy layout happens to equal the size of this
MessagePack prefix, so the same skip-and-unmask step works for both forms — which is
why one implementation covers them.

`parseResourceUri` decodes both and reports which one it found (`format: msgpack` /
`format: obfuscated`), plus the profile and cipher names when present (e.g. `DEFAULT`,
`ChaCha`). Both converge on the same pipeline: `masterKey` → `HMAC-SHA256(…, fileName)`
→ ChaCha20 with the 8-byte iv.

ChaCha20 has two common layouts (64-bit counter / 64-bit nonce, and RFC 7539's 32-bit
counter / 96-bit nonce). The tool tries the original layout first, then the RFC one, and
keeps whichever produces a hash match — so it works against either server build instead of
assuming. `--verbose` shows which one won.

### Why the output can be trusted

Every archive and stream carries a server-computed SHA-1. The tool reports
`[verified]` only when the bytes on disk match it, and warns loudly with `[UNVERIFIED]`
otherwise. A silent corruption or a wrong decryption key cannot masquerade as success.

## Servers that encrypt resources

A lot of roleplay servers — and essentially every commercial "resource protection"
pack — patch `getConfiguration` to add a per-resource `uri` key blob and serve
`resource.rpf` **encrypted**, so the client decrypts it in memory and nothing readable
sits on disk. The advertised SHA-1 still refers to the plaintext, so verification
keeps working, but the key derivation is vendor-specific.

Two stages handle this:

**1. Probe matrix — automatic, cheap.** Before any full-file decryption the tool tries
4 key derivations × 10 cipher layouts against the first 512 bytes and looks for the
`RPF2` magic:

| Key derivations | Cipher layouts |
| --- | --- |
| `HMAC-SHA256(key, fileName)` · `HMAC-SHA256(key, "resource.rpf")` · raw key · `SHA-256(key ‖ fileName)` | ChaCha20 (8-byte nonce, counter 0/1) · ChaCha20 (12-byte nonce, both paddings, counter 0/1) · XChaCha20 · AES-256-CTR (both 16-byte IV paddings) |

Whichever combination matches is used to decrypt the whole file, and the result must
still match the advertised SHA-1 before it is trusted.

**2. `--diagnose` — opt-in, slower.** If the matrix misses, this searches the key-blob
parameter space: header length 0–24, obfuscation byte 0–255, trailing padding 0–2
(~19k candidates, a couple of seconds). A working candidate recovers the resource and
it is processed normally. If nothing works, it writes
`<out>/<server>/_diagnostics/<resource>/`:

- `<file>.served.bin` — the first 1 MiB of the encrypted payload
- `<file>.meta.json` — the `uri`, both hashes, sizes, and the full probe output

Those two files are enough to work the scheme out offline.

If `--diagnose` reports everything as unrecognised, the payload is most likely keyed
per session (a key that never reaches the client in a form derivable from the `uri`)
rather than encrypted with a static per-resource key. At that point no client-side
tool can recover it without hooking the game process.

Start with one small resource rather than the whole server:

```bash
node src/cli.js -s 194.50.0.77:30120 --only oxmysql --diagnose -v
```

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Not a valid client.` | You are not connected to that server from this IP. Join it, keep it open, retry. Or use `--token`. |
| `Client is still connecting.` | You are still in the loading screen. Wait until you are actually in, then retry. |
| `Rate limit exceeded.` | Per-token limit on `getConfiguration`. Wait ~30 s. |
| `HTTP 403 ... not allowed to access this endpoint` | Server sets `sv_httpFileServerProxyOnly`; only a proxy may fetch non-`resource.rpf` files. Archive dumps still work; streams will not. |
| `HTTP 404 ... missing requested file` | File is not in the server's `filePairs`/streaming list — often a protected or escrow-only resource. |
| `could not recover plaintext` | The server encrypts resources with a scheme this build does not know. Re-run that resource with `--diagnose`; see [Servers that encrypt resources](#servers-that-encrypt-resources). |
| Empty `resources` | Filter too narrow, or every resource is `server_only`. Check `--info` for the public list. |

## Layout

```
start.cmd        double-click launcher (runs the wizard)
src/wizard.js    easy mode: asks 3 questions, then calls the CLI
src/cli.js       argument parsing, orchestration, reporting
src/brand.js     author, copyright and community link (single source)
src/resolver.js  cfx.re join codes / fivem:// links -> real endpoint
src/fxserver.js  /client + /files client, streaming, redirects, timeouts
src/dumper.js    payload resolution (verify/decrypt), extraction, streams
src/probe.js     decryption-profile probing + brute-force recovery
src/keyblob.js   MessagePack key-blob decoder
src/rpf2.js      RPF2 packfile reader
src/crypto.js    ChaCha20 / XChaCha20, key derivation
src/settings.js  remembers your last answers
src/util.js      paths, URLs, hashing, logging
```

## References

- `citizen-server-impl/src/GetConfigurationMethod.cpp` — config endpoint and its auth checks
- `citizen-server-impl/src/ResourceConfigurationCacheComponent.cpp` — `files`/`streamFiles` shape
- `citizen-server-impl/src/ResourceFilesComponent.cpp` — RPF2 writer, SHA-1 of the plaintext
- `citizen-server-impl/src/FilesHttpHandler.cpp` — `/files/…` behaviour
- RFC 8439 — ChaCha20-Poly1305, block-function and encryption test vectors

---

## Author & credits

**fivem-dumper** — built, documented and maintained by **Mohammed**.

- **Discord:** https://discord.gg/6G6m74Ynbw
- **Community:** **http** — the server this project lives on. Programming, tooling,
  and the sort of work most servers would rather not talk about, explained properly.
- **Support, updates, and the source of this release:** that Discord, nowhere else.

Every file in `src/` opens with the author header, the CLI and wizard banners print
it on every run, `start.cmd` shows it before anything happens, and every
`manifest.json` written by the tool records it. A build with the credit stripped is
not a build from here.

### What you may and may not do

| Allowed | Not allowed |
| --- | --- |
| Use it, share it unchanged, fork it for yourself | Sell it, paywall it, gate it behind a key |
| Post it on your own server with the credit intact | Remove the author, the copyright or the link |
| Modify it and publish the modified version | Rename it, rebrand it, or claim it as your own |

Full text: [LICENSE](LICENSE).

© 2026 Mohammed. All rights reserved.

> **Disclaimer** — fivem-dumper is published **for educational and research
> purposes only**. It exists to show how the FXServer client-download path and the
> RPF2 container work. You are solely responsible for how you use it. The author is
> **not responsible for any misuse** of this software, for any damage it causes, or
> for any consequence of running it against a server you do not control.

