# NSIF — No Shit Installer File

**On-disk format specification, version 0.1 (draft, v0)**

Status: draft, pending approval. Nothing here is stable until v1.0.
Document date: 2026-11-09.

---

## 0. Scope and non-goals

NSIF replaces `.iso` for distributing bootable Linux installers and live
images. The hard constraint, from which everything else follows:

> **A `.nsif` file is a valid GPT disk image. `dd if=x.nsif of=/dev/sdX`
> produces a bootable disk. No special tooling is required to flash it.**

### In scope for v0

- UEFI x86_64 boot.
- 512-byte logical sectors.
- Self-describing, hash-verifiable, zstd-compressed payload.
- Content-defined chunking for delta updates over HTTP range requests.
- Detached Ed25519 signature over the manifest.
- A persistence partition created on first boot from unused disk space.

### Explicitly out of scope for v0

- Legacy BIOS boot, El Torito, ISO 9660, hybrid MBR.
- 4Kn media (4096-byte logical sectors).
- Architectures other than `x86_64`.
- Secure Boot (see §12).
- Writable root. The NSIF payload is read-only forever; writes go to the
  persistence overlay.

---

## 1. Terminology

- **Image file** — the `.nsif` file itself.
- **Target disk** — the block device the image file was written to.
- **Payload partition** — GPT partition holding the NSIF container (§4).
- **Rootfs image** — the single uncompressed byte stream that the payload
  encodes. It is a filesystem image (EROFS, SquashFS or ext4), not an
  archive.
- **Chunk** — a variable-length, contiguous run of the rootfs image,
  produced by FastCDC, stored individually compressed.
- **MUST / SHOULD / MAY** — RFC 2119.

All multi-byte integers in binary structures defined by this document are
**little-endian**, unless the UEFI specification says otherwise for a
structure it owns. All offsets are byte offsets, zero-based, relative to the
start of the structure that declares them.

---

## 2. Why CBOR and not JSON

The manifest is **deterministic CBOR** (RFC 8949, §4.2.1 "Core Deterministic
Encoding Requirements"), with the additional restrictions in §5.1.

The decision is driven by four things, in priority order:

1. **The signature is over manifest bytes, so the encoding must be
   canonical.** A second implementation has to be able to re-encode a
   manifest and get the same bytes, or signatures become unverifiable after
   any round-trip. JSON has no canonical form in practice: key order,
   number formatting (`1e3` vs `1000`), string escaping (`/` vs `\/`,
   `é` vs UTF-8), and whitespace are all free. RFC 8785 (JCS) fixes
   this on paper, but almost no JSON library implements it, and its number
   rules route through IEEE-754 double. CBOR's deterministic profile is
   three short rules (definite lengths, shortest-form head, bytewise-sorted
   map keys) and is trivial to verify byte-for-byte.

2. **u64 offsets must survive the round trip exactly.** JSON numbers are
   doubles in most parsers; values above 2^53 silently lose precision. Every
   offset and length in this format is a u64. CBOR has native unsigned
   integers up to 2^64-1.

3. **Size.** The chunk list dominates the manifest. A chunk entry is a
   32-byte hash plus four integers. In CBOR that is 32 + 2 header bytes for
   the hash, and 1–9 bytes per integer: roughly **60–75 bytes per chunk**.
   In JSON, the hash alone is 64 hex characters plus quotes, and the
   integers are decimal with field names: roughly **200–260 bytes per
   chunk** even with positional arrays and base64. For a 2 GiB rootfs at
   64 KiB average chunk size (~32 700 chunks) that is ~2.3 MB versus
   ~7.5 MB. `nsif update` downloads the manifest before it can download
   anything else, and `nsif-boot` parses it inside an initramfs under a
   fixed memory budget. The 3× matters in both places.

4. **Parser attack surface.** `nsif-boot` is a static binary that parses
   attacker-influenced bytes before it has verified anything except a hash.
   A CBOR reader with no floats, no tags, no indefinite-length items and no
   recursion beyond depth 4 is a few hundred lines with easy bounds
   checking. A conforming JSON parser is larger and has worse failure modes
   (number parsing, surrogate pairs).

**Ergonomics are not lost.** `nsif info --json` and `nsif diff --json` emit
JSON for humans and scripts. JSON is an output format, never a storage or
signing format.

---

## 3. Disk layout

Logical sector size (LSS) is **512 bytes**, normative for v0. An
implementation MUST refuse to parse a `.nsif` whose GPT implies anything
else.

Alignment: every partition starts and ends on a **1 MiB boundary** (2048
sectors).

```
LBA           Contents
------------- ----------------------------------------------------------
0             Protective MBR (UEFI 2.10 §5.2.3)
1             Primary GPT header
2 .. 33       Primary GPT partition entry array (128 entries x 128 B)
34 .. 2047    Zero padding (alignment reserve)
2048 .. a     Partition 1 — EFI System Partition, FAT32
a+1 .. b      Partition 2 — NSIF payload
b+1 .. c      Zero padding to 1 MiB boundary (may be empty)
L-33 .. L-2   Backup GPT partition entry array
L-1           Backup GPT header
```

where `L` = total image size in sectors. `L` MUST be a multiple of 2048
(the image file size is a whole number of MiB), so that `dd` onto a disk
whose size is also MiB-aligned leaves no ragged tail.

### 3.1 Protective MBR

- Bytes 0..439: zero. (No bootstrap code. v0 does not boot BIOS.)
- Bytes 440..443 (disk signature): zero.
- Bytes 444..445: zero.
- One partition record at offset 446:
  - boot indicator `0x00`
  - starting CHS `0x00 0x02 0x00`
  - OS type `0xEE`
  - ending CHS `0xFF 0xFF 0xFF`
  - starting LBA `1`
  - size in LBA `min(L - 1, 0xFFFFFFFF)`
- Partition records 2–4: zero.
- Signature `0x55 0xAA` at offset 510.

### 3.2 GPT headers

Per UEFI 2.10 §5.3. Normative values for v0:

| Field | Value |
|---|---|
| Signature | `"EFI PART"` (`45 46 49 20 50 41 52 54`) |
| Revision | `0x00010000` |
| HeaderSize | `92` |
| MyLBA (primary) | `1` |
| AlternateLBA (primary) | `L - 1` |
| FirstUsableLBA | `34` |
| LastUsableLBA | `L - 34` |
| NumberOfPartitionEntries | `128` |
| SizeOfPartitionEntry | `128` |
| PartitionEntryLBA (primary) | `2` |
| PartitionEntryLBA (backup) | `L - 33` |

`DiskGUID`, `CRC32` of the header, and `CRC32` of the entry array are as
specified by UEFI. Header bytes 92..511 MUST be zero. The CRC is the
standard CRC-32 (IEEE 802.3, reflected, poly `0xEDB88320`, init
`0xFFFFFFFF`, final xor `0xFFFFFFFF`) — *not* CRC-32C.

The backup header is identical to the primary except `MyLBA`,
`AlternateLBA`, `PartitionEntryLBA` and `CRC32`.

### 3.3 Partition entries

| # | Type GUID | Name (UTF-16LE, 36 chars) | Attributes | Contents |
|---|---|---|---|---|
| 1 | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | `NSIF ESP` | 0 | FAT32, §6 |
| 2 | `285621D5-0502-4ECF-9CEE-75F40014C6B3` | `NSIF PAYLOAD` | `0x1000000000000000` (RequiredPartition) | §4 |
| 3 | `9A5B35C3-3C4D-4731-9E97-0936CC569006` | `NSIF PERSIST` | 0 | §8, created on first boot, absent in the image file |

Partition type GUIDs 2 and 3 are **assigned by this specification** and are
stable for the life of the format. GUID bytes on disk follow the
mixed-endian GUID encoding used by GPT (first three fields little-endian,
last two big-endian), i.e. `285621D5-...` is stored as
`D5 21 56 28 02 05 CF 4E 9C EE 75 F4 00 14 C6 B3`.

Partition 1 has a minimum size of 32 MiB and is sized to `ceil` of its
content to the next MiB, with at least 8 MiB of slack. Partition 2 is sized
to `ceil(payload_used_len, 1 MiB)`.

### 3.4 Finding things at runtime

`nsif-boot` and `nsif verify` MUST locate the payload by **scanning the GPT
of each candidate whole-disk device for a partition whose type GUID is the
NSIF payload GUID**, not by partition index, label, or kernel partition
name. If more than one disk carries a payload partition, the one on the same
disk as the ESP the firmware booted from wins (`LoaderDevicePartUUID` EFI
variable when available; otherwise the lowest-numbered disk, with a warning).

---

## 4. Payload partition layout

```
Partition-relative offset   Contents
------------------------    ------------------------------------------
0                           Payload header, 4096 bytes (§4.1)
header_len                  Manifest, manifest_len bytes (§5)
...                         Signature block, signature_len bytes (§7)
...                         Zero padding to a 4096-byte boundary
chunk_data_offset           Compressed chunk data, chunk_data_len bytes
payload_used_len            Zero padding to end of partition
```

`manifest_offset`, `signature_offset` and `chunk_data_offset` MUST each be a
multiple of 4096. A reader MUST NOT assume the order above beyond what the
header says; it MUST validate the ranges per §4.2.

### 4.1 Payload header

Fixed 4096 bytes at partition-relative offset 0.

| Offset | Size | Type | Field | v0 constraint |
|---|---|---|---|---|
| 0 | 8 | bytes | `magic` | `4E 53 49 46 50 41 59 00` (`"NSIFPAY\0"`) |
| 8 | 2 | u16 | `version_major` | `0` |
| 10 | 2 | u16 | `version_minor` | `1` |
| 12 | 4 | u32 | `header_len` | `4096` |
| 16 | 8 | u64 | `manifest_offset` | `>= header_len`, 4096-aligned |
| 24 | 8 | u64 | `manifest_len` | `1 ..= 67_108_864` |
| 32 | 8 | u64 | `signature_offset` | `>= header_len`, 4096-aligned |
| 40 | 8 | u64 | `signature_len` | `128` in v0, `<= 4096` accepted |
| 48 | 8 | u64 | `chunk_data_offset` | `>= header_len`, 4096-aligned |
| 56 | 8 | u64 | `chunk_data_len` | `<= payload_used_len` |
| 64 | 32 | bytes | `manifest_hash` | BLAKE3-256 of the manifest bytes |
| 96 | 8 | u64 | `payload_used_len` | `<= partition size in bytes` |
| 104 | 8 | u64 | `flags` | `0`; unknown bits MUST be rejected |
| 112 | 4 | u32 | `header_crc32c` | §4.1.1 |
| 116 | 12 | bytes | `reserved` | zero |
| 128 | 3968 | bytes | `reserved2` | zero |

#### 4.1.1 `header_crc32c`

CRC-32C (Castagnoli, reflected, poly `0x82F63B78`, init `0xFFFFFFFF`, final
xor `0xFFFFFFFF`) computed over bytes `0 .. header_len` of the header with
bytes `112..116` set to zero. A reader MUST check it before using any other
field except `magic`, `header_len` and `version_major`.

The header is **not** covered by the signature. It is a pointer block; a
corrupted or malicious pointer can only cause `manifest_hash` or the
signature check to fail. A reader MUST NOT treat a valid `header_crc32c` as
authentication of anything.

### 4.1.2 Version handling

- `version_major != 0` → **reject**, hard error.
- `version_major == 0`, `version_minor > 1` → **reject** in v0. (Pre-1.0
  minors are not promised to be compatible. From 1.0 onward, an unknown
  minor with a known major MUST be accepted and unknown fields ignored.)

### 4.2 Mandatory range validation

Let `P` = size of the payload partition in bytes, taken from the GPT, and
`U` = `payload_used_len`.

A reader MUST reject the payload unless **all** of the following hold, with
every addition performed as a checked u64 add (overflow → reject):

1. `header_len == 4096` and `U <= P` and `U >= header_len`.
2. For each of the three regions `(off, len)` in
   `{(manifest_offset, manifest_len), (signature_offset, signature_len),
   (chunk_data_offset, chunk_data_len)}`:
   `off >= header_len`, `off + len <= U`.
3. The three regions are pairwise **disjoint**.
4. `manifest_len`, `signature_len` and the chunk count are within the caps
   in §9.
5. BLAKE3-256 over the `manifest_len` bytes at `manifest_offset` equals
   `manifest_hash`.

Only after (1)–(5) may the manifest be parsed.

---

## 5. Manifest

Deterministic CBOR. The manifest is a single CBOR map. Keys are text
strings. The chunk and ESP-file lists are arrays of **positional arrays**,
not arrays of maps, to avoid repeating key names tens of thousands of times.

### 5.1 Deterministic encoding profile

Beyond RFC 8949 §4.2.1, a v0 manifest MUST satisfy, and a v0 parser MUST
enforce:

1. All lengths definite. No indefinite-length items (`0x5F`, `0x7F`,
   `0x9F`, `0xBF`).
2. Shortest-form argument encoding for every head (no `0x18 0x0A` for 10).
3. Map keys sorted ascending by **bytewise lexicographic comparison of
   their encoded bytes**.
4. No duplicate map keys.
5. No major type 7 floats (`0xF9`–`0xFB`), no `undefined`, no tags (major
   type 6). `true`/`false` are permitted.
6. Text strings MUST be well-formed UTF-8. No normalisation is required or
   performed; byte equality is identity.
7. Maximum nesting depth 4.
8. No trailing bytes after the top-level item within `manifest_len`.

A manifest that violates any of these MUST be rejected, even if it parses.
This is what makes "re-encode and compare" a valid implementation test.

### 5.2 Schema (CDDL)

```cddl
manifest = {
  "arch"              => "x86_64",
  "build_date"        => uint,          ; Unix seconds UTC
  "chunking"          => chunking,
  "chunks"            => [+ chunk],
  "cmdline"           => tstr,          ; informational copy of the ESP cmdline
  "codec"             => tstr,          ; "zstd" or "none"
  "codec_params"      => { * tstr => (uint / tstr / bool) },
  "esp_files"         => [* espfile],
  "format"            => "nsif-manifest",
  "image_version"     => tstr,          ; display version, e.g. "0.1.0"
  "metadata"          => { * tstr => tstr },
  "name"              => tstr,
  "rootfs_fstype"     => tstr,          ; "erofs" / "squashfs" / "ext4"
  "rootfs_hash"       => bstr .size 32, ; BLAKE3-256 of the whole rootfs image
  "rootfs_size"       => uint,          ; uncompressed rootfs image size
  "version"           => 1,             ; manifest schema version
  "version_ordinal"   => uint,          ; monotonic; used by `update`
}

chunking = {
  "algo"          => "fastcdc",
  "avg"           => uint,
  "max"           => uint,
  "min"           => uint,
  "normalization" => uint,              ; 0..3
  "seed"          => uint,              ; gear-table seed, 0 in v0
}

; [hash, uncompressed_offset, uncompressed_len, compressed_offset, compressed_len]
chunk = [bstr .size 32, uint, uint, uint, uint]

; [path, size, hash]  -- path is ESP-absolute, '/'-separated, e.g. "/EFI/BOOT/BOOTX64.EFI"
espfile = [tstr, uint, bstr .size 32]
```

Note the key order in the CDDL above is already the deterministic order
(bytewise on the encoded text strings), so an implementation can emit the
fields in that written order.

### 5.3 Manifest invariants

A reader MUST reject the manifest unless all of the following hold:

1. `format == "nsif-manifest"` and `version == 1`.
2. `arch == "x86_64"`.
3. `codec` is a known codec id (§10). `codec_params` contains only keys that
   codec declares.
4. `rootfs_fstype` is one of `"erofs"`, `"squashfs"`, `"ext4"`.
5. `chunking.algo == "fastcdc"`,
   `16384 <= min <= avg <= max <= 16777216`, `normalization <= 3`.
6. `chunks` is non-empty, length `<= 4_194_304`.
7. **Uncompressed coverage is exact and contiguous.** `chunks[0].uoff == 0`;
   for every `i > 0`, `chunks[i].uoff == chunks[i-1].uoff +
   chunks[i-1].ulen`; and `last.uoff + last.ulen == rootfs_size`. Every
   `ulen` satisfies `1 <= ulen <= chunking.max`.
8. **Compressed extents are in range.** For every chunk,
   `coff + clen <= chunk_data_len` (checked add), `clen >= 1`, and
   `clen <= ulen + codec_max_expansion(ulen)` (§10.2).
9. **Compressed extents do not partially overlap.** For any two chunks `i`,
   `j`: either `[coff_i, coff_i+clen_i)` and `[coff_j, coff_j+clen_j)` are
   disjoint, or `coff_i == coff_j && clen_i == clen_j && hash_i == hash_j`
   (deduplication of identical chunks). Any other overlap MUST be rejected.
   Implementation note: sort distinct `(coff, clen)` pairs by `coff` and
   check adjacency in one pass.
10. `rootfs_size >= 1` and `rootfs_size <= 1 TiB`.
11. `esp_files` length `<= 65_536`; each path is `<= 1024` bytes, begins
    with `/`, contains no `.` or `..` component, no empty component, no
    backslash, no NUL, and no duplicate paths. Paths are compared
    **case-insensitively** for duplicate detection, because FAT is
    case-insensitive.
12. `name`, `image_version`, `cmdline` each `<= 4096` bytes; `metadata` has
    `<= 64` entries, each key `<= 128` and value `<= 4096` bytes.

`rootfs_hash` is the BLAKE3-256 of the concatenation of all chunks'
uncompressed bytes in order. It is redundant with the per-chunk hashes but
makes `verify` able to state one number, and catches a manifest whose chunk
list has been reordered consistently.

### 5.4 Chunk addressing

`chunks` is sorted by `uoff` and exactly tiles `[0, rootfs_size)`, so a read
of `[off, off+len)` is served by binary search for `off` over `uoff` and
then walking forward. This is the random-read property. `coff`/`clen` give
`update` the exact HTTP byte range per chunk; chunks are independently
compressed, so no ranges need to be merged for correctness (they MAY be
coalesced for efficiency when adjacent).

---

## 6. ESP contents

FAT32, 512-byte sectors, 4096-byte (8-sector) clusters, 2 FATs, 32 reserved
sectors, volume label `NSIF`.

```
/EFI/BOOT/BOOTX64.EFI        bootloader (systemd-boot in v0's reference pack)
/EFI/nsif/vmlinuz            kernel
/EFI/nsif/initrd.img         initramfs containing nsif-boot
/loader/loader.conf          systemd-boot config
/loader/entries/nsif.conf    Boot Loader Spec Type #1 entry
```

`/loader/entries/nsif.conf`:

```
title    <name> <image_version>
linux    /EFI/nsif/vmlinuz
initrd   /EFI/nsif/initrd.img
options  <cmdline>
```

`loader.conf` is `timeout 0\ndefault nsif.conf\nconsole-mode keep\n`.

Every regular file on the ESP MUST appear in `esp_files` with its exact size
and BLAKE3-256. `nsif verify` checks all of them. Directories are not
listed.

Unified kernel images (a single PE at `/EFI/Linux/*.efi`) are a planned v1
addition and are not produced by v0.

### 6.1 Deterministic FAT32

`nsif pack` writes FAT32 itself, in userspace, with no mounting and no
external tools. To make the bytes a function of the inputs only:

- `BS_VolID` = first 4 bytes of `derive(b"nsif.fat.volid")` (§11.1).
- All directory entry timestamps = `build_date`, converted to FAT local
  time with **UTC as the local zone** and the 10 ms field set to 0.
- Directory entries are written in **ascending byte order of the uppercased
  8.3 short name**, with LFN entries immediately preceding their short
  entry.
- Short-name collision resolution uses the `~1`, `~2`, … sequence in that
  same iteration order.
- Clusters are allocated strictly ascending in directory-entry order, file
  data written contiguously, no gaps.
- All reserved and unused bytes, all slack in the last cluster of each file,
  and all free clusters are zero.
- `BPB_FSInfo` free-cluster count and next-free hints are written with the
  true values (not `0xFFFFFFFF`).

---

## 7. Signature block

128 bytes in v0.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | `magic` | `"NSG1"` (`4E 53 47 31`) |
| 4 | 1 | `algo` | `1` = Ed25519 |
| 5 | 1 | `reserved` | `0` |
| 6 | 2 | `sig_len` | `64` |
| 8 | 32 | `public_key` | Ed25519 public key, **informational only** |
| 40 | 64 | `signature` | raw Ed25519 signature |
| 104 | 24 | `reserved2` | zero |

### 7.1 Signed message

```
msg = "NSIF-SIG-v1\x00"            (12 bytes, domain separation)
    || u16le(version_major)
    || u16le(version_minor)
    || u64le(manifest_len)
    || manifest_bytes              (exactly manifest_len bytes)
```

`signature = Ed25519-sign(sk, msg)`. Verification is Ed25519-verify with
the **caller-supplied** public key. `manifest_len` is inside the message so
that no two different (length, bytes) pairs can produce the same message.

Signature verification MUST use RFC 8032 Ed25519 with the strictness of
`ed25519-dalek`'s `verify_strict`: reject non-canonical `R`/`A` encodings and
reject small-order `A`. This keeps a signature from being valid under more
than one key.

### 7.2 Trust

**The `public_key` field in the file proves nothing.** Anyone can generate a
key, sign a manifest, and embed the matching public key. `nsif verify` and
`nsif update` MUST take the public key from `--pubkey <file>` or from a
trusted keyring path configured by the operator, and MUST NOT fall back to
the embedded key. The embedded key exists only so `nsif info` can print its
fingerprint, letting a user see *which* key they would need; `info` MUST
print it with an explicit "unverified" marker.

---

## 8. Persistence partition

The image file ships with partitions 1 and 2 only. On first boot,
`nsif-boot` tries to create partition 3 from the space after partition 2.

### 8.1 Algorithm

Let `D` = target disk size in sectors (from the device, not the GPT),
`E` = last sector of partition 2.

1. If a partition with the NSIF persistence type GUID already exists, use
   it and stop.
2. If the disk is read-only, or `D - E < 2 * 2048 + 64` (less than ~64 MiB
   of usable tail), go to §8.3.
3. Verify both existing GPT copies parse and their CRCs match. If the
   primary and backup disagree, **do nothing** and go to §8.3 — repairing a
   damaged GPT is not this program's job.
4. **Relocate the backup GPT to the true end of the disk.** Write the backup
   partition entry array at `D - 33` and the backup header at `D - 1`, with
   `MyLBA = D - 1`, `AlternateLBA = 1`, `PartitionEntryLBA = D - 33`,
   `LastUsableLBA = D - 34`. Update the primary header's `AlternateLBA` and
   `LastUsableLBA` to match, recompute both CRCs.
5. `fsync`/`BLKFLSBUF` the device.
6. Compute the new partition: `start = align_up(E + 1, 2048)`,
   `end = D - 34` rounded down to `align_down(D - 33, 2048) - 1`. Write
   entry 3 with the persistence type GUID, name `NSIF PERSIST`, a GUID from
   §11.1 derived from the disk GUID, into both entry arrays; recompute both
   entry-array CRCs and both header CRCs; write backup first, then primary.
7. `fsync`, then `BLKRRPART` (or write to
   `/sys/class/block/<disk>/uevent`) to get the kernel to see partition 3.
8. Format it: `mke2fs -q -t ext4 -F -m 0 -L nsif-persist <dev>`. `mke2fs`
   MUST be present in the initramfs. If it is missing or fails, go to §8.3.
9. Create `overlay/upper` and `overlay/work` on it.

Steps 4 and 6 MUST write the backup GPT before the primary, so that a power
loss mid-operation leaves the primary authoritative and unchanged.

`nsif-boot` MUST NOT modify partitions 1 or 2, MUST NOT move them, and MUST
NOT write to any sector inside them, at any point, ever.

### 8.2 Overlay mount

```
lower = /run/nsif/lower          (read-only mount of the NBD device)
upper = <persist>/overlay/upper
work  = <persist>/overlay/work
mount -t overlay nsif-root -o lowerdir=$lower,upperdir=$upper,workdir=$work /sysroot
```

### 8.3 Fallback: tmpfs overlay

If persistence cannot be created or found:

```
mount -t tmpfs -o mode=0755,size=50% nsif-tmp /run/nsif/vol
upper = /run/nsif/vol/upper ; work = /run/nsif/vol/work
```

and print, to both the console and the kernel log, at warning level:

```
nsif: WARNING: no persistence partition (<reason>).
nsif: Changes are in RAM only and WILL BE LOST on reboot.
```

The boot MUST continue. A read-only stick is a supported configuration.

---

## 9. Hard limits (normative)

Every one of these is a reject, not a clamp.

| Quantity | Limit |
|---|---|
| `header_len` | exactly 4096 |
| `manifest_len` | 64 MiB |
| `signature_len` | 4096 |
| chunk count | 4 194 304 (2^22) |
| chunk `ulen` | 1 B .. 16 MiB |
| chunk `clen` | `ulen + max_expansion(ulen)`, and ≤ 16 MiB + 64 KiB |
| `rootfs_size` | 1 TiB |
| `esp_files` count | 65 536 |
| ESP path length | 1024 B |
| `metadata` entries | 64 |
| CBOR nesting depth | 4 |
| `nsif-boot` chunk cache | bounded by `rd.nsif.cache=` (default 192 MiB) |
| decompressed output per chunk | exactly `ulen`; a codec that produces more or fewer bytes is an error |

Decompression is always into a buffer of exactly `ulen` bytes, so a
decompression bomb is impossible by construction: the declared size is the
allocation size, and it is capped at 16 MiB.

---

## 10. Codecs

### 10.1 Codec trait

```rust
pub trait Codec {
    /// Stable registry id, recorded in the manifest.
    fn id(&self) -> &'static str;
    /// Parameters, recorded in `codec_params`. Keys must be stable.
    fn params(&self) -> BTreeMap<String, ParamValue>;
    /// Compress `src` into a fresh Vec. Must be deterministic for a given
    /// (build of this codec, params, src).
    fn compress(&self, src: &[u8]) -> Result<Vec<u8>>;
    /// Decompress `src` into exactly `dst.len()` bytes. Must fail if the
    /// output would be any other length.
    fn decompress(&self, src: &[u8], dst: &mut [u8]) -> Result<()>;
    /// Upper bound on output size for an input of `n` bytes.
    fn max_expansion(&self, n: usize) -> usize;
}
```

Registry for v0:

| id | Meaning |
|---|---|
| `"zstd"` | zstd, `codec_params = {"level": <1..22>, "long": bool}`. Default level 19, `long: false`. No dictionary in v0. Frames are single-frame, with content size in the frame header, no checksum (the BLAKE3 hash is the checksum). |
| `"none"` | identity. `clen == ulen`. For testing and for incompressible payloads. |

A reader encountering an unknown `codec` id MUST reject the image with a
clear "unsupported codec" error naming the id.

### 10.2 `max_expansion`

For zstd: `n + (n >> 8) + 64`. For `none`: `0`. §5.3(8) uses the value for
the manifest's declared codec.

### 10.3 Reproducibility caveat

zstd output is deterministic for a fixed library version and parameters, but
**not guaranteed identical across zstd versions**. The byte-identical-rebuild
guarantee therefore holds for "same inputs, same `build_date`, same `nsif`
binary". `metadata` records `zstd.version` so a mismatch is diagnosable
rather than mysterious. This is stated rather than hidden because it is the
one place the reproducibility claim has a seam.

---

## 11. Reproducible builds

Given identical `--rootfs`, `--kernel`, `--initramfs`, `--bootloader`,
`--cmdline`, metadata, `--build-date`, codec settings, chunking parameters
and signing key, `nsif pack` MUST produce a byte-identical file.

Sources of nondeterminism and how each is removed:

| Source | Resolution |
|---|---|
| GPT `DiskGUID`, partition GUIDs | derived, §11.1 |
| FAT32 volume ID | derived, §11.1 |
| File timestamps in FAT | all set to `build_date` |
| FAT directory order | sorted, §6.1 |
| Cluster allocation order | strictly ascending, §6.1 |
| Uninitialised slack | explicitly zeroed |
| `build_date` | required input; `--build-date <unix>` or `SOURCE_DATE_EPOCH`. No implicit "now" — `pack` errors out if neither is given, rather than silently producing an unreproducible file. |
| Partition sizes | pure function of content sizes and the alignment rules |
| zstd | pinned version + params (§10.3) |
| Chunk order | FastCDC is deterministic; chunks are emitted in rootfs order |
| Dedup choice | the **first** occurrence of a hash owns the compressed extent; later identical chunks reuse its `(coff, clen)` |
| HashMap iteration | no map iteration order ever reaches the output; all serialised collections are sorted |
| Ed25519 | RFC 8032 Ed25519 is deterministic (no nonce) |

### 11.1 GUID derivation

```
derive(domain) = BLAKE3_keyed_or_derive_key(
                   context = "nsif.v0.guid",
                   material = domain || 0x00
                            || u64le(build_date)
                            || name_utf8 || 0x00
                            || image_version_utf8 || 0x00 )
```

Take the first 16 bytes. Set the version nibble to 4 and the variant bits to
`10` (RFC 4122) so the result is a well-formed random-looking UUIDv4. The
domains used are `b"nsif.disk"`, `b"nsif.part.esp"`, `b"nsif.part.payload"`,
`b"nsif.fat.volid"`.

The persistence partition GUID is derived at boot from the on-disk
`DiskGUID` with domain `b"nsif.part.persist"`, so it is stable per target
disk without `nsif-boot` needing the manifest.

---

## 12. Trust model — read this before claiming anything

**Secure Boot is out of scope for v0, and that has consequences that must
not be papered over.**

- The ESP is **unsigned**. `BOOTX64.EFI`, the kernel, the initramfs and
  therefore `nsif-boot` itself are all plain files on a FAT32 partition.
- Anyone who can write to the media can replace `nsif-boot` with a program
  that skips every hash check, or replace the kernel outright.
- Therefore: **the boot-time hash verification in §13 detects corruption,
  not tampering.** It catches a bad flash, a dying USB stick, bit rot, a
  truncated download. It does not catch an adversary. Calling it a security
  guarantee would be false.
- The Ed25519 signature is meaningful **only** when checked by `nsif verify`
  or `nsif update` on a machine you trust, with a key you obtained out of
  band. In that setting it does authenticate the manifest, and through the
  manifest's hashes, the rootfs and the ESP files.
- `nsif-boot` MAY check the signature at boot if a key is baked into the
  initramfs, and reports the result, but that check is **advisory**: the
  key and the checker live on the same unsigned partition as the thing being
  checked.

v1 is expected to address this with a signed UKI, Secure Boot shim
enrolment, and measured boot (the manifest hash extended into a TPM PCR).
Until then, the above is the honest statement, and it appears in the README
in the same words.

---

## 13. Boot-time behaviour of `nsif-boot`

`nsif-boot` is a **statically linked** binary (`x86_64-unknown-linux-musl`)
in the initramfs. It serves the root filesystem, so it must outlive
`switch_root` and survive until the final `umount` at shutdown. Everything
in this section is a requirement, not advice: getting any of it wrong
produces a hang at shutdown or a deadlock under memory pressure, both of
which look like "the distro is broken".

### 13.1 Why NBD in v0 (and ublk later)

See PLAN.md §2 for the full comparison. The short version: **v0 uses NBD**,
behind a `BlockBackend` trait, with a ublk backend planned for v1.
`CONFIG_BLK_DEV_NBD` is in essentially every shipping kernel;
`CONFIG_BLK_DEV_UBLK` is not — the Ubuntu 24.04 `linux-image-virtual`
(6.8.0) package used for this project's own tests ships `nbd.ko` and no
`ublk_drv.ko` at all. Since the kernel in a `.nsif` is supplied by the
distro building the image, requiring ublk would mean requiring a kernel
config change from every publisher. NBD does not.

**Kernel requirements, v0:** `CONFIG_BLK_DEV_NBD` (module or built-in),
`CONFIG_OVERLAY_FS`, `CONFIG_EROFS_FS` (or SquashFS/ext4 to match
`rootfs_fstype`), `CONFIG_TMPFS`, `CONFIG_EFI_PARTITION`, and
`PR_SET_IO_FLUSHER` (Linux ≥ 5.6). The practical floor is **Linux 5.6**.

### 13.2 Transport setup

1. `modprobe nbd nbds_max=1 max_part=0` (or rely on a built-in driver).
2. Create a `socketpair(AF_UNIX, SOCK_STREAM, 0)`.
3. Configure the device through the `nbd` **generic netlink** family
   (`NBD_CMD_CONNECT`) with: `NBD_ATTR_INDEX=0`,
   `NBD_ATTR_SIZE_BYTES=rootfs_size`, `NBD_ATTR_BLOCK_SIZE_BYTES=4096`,
   `NBD_ATTR_SERVER_FLAGS = NBD_FLAG_READ_ONLY | NBD_FLAG_SEND_FLUSH`,
   `NBD_ATTR_TIMEOUT=0`, and one `NBD_SOCK_FD` = the kernel-side end of the
   socketpair. No `nbd-client` binary, no TCP, no loopback networking, no
   network namespace interaction.
4. Set `/sys/block/nbd0/ro` is implied by `NBD_FLAG_READ_ONLY`; also set
   `/sys/block/nbd0/queue/rotational = 0` and
   `read_ahead_kb = 256` (one chunk's worth, to avoid read amplification
   past chunk boundaries).

**Risk, to be settled in M4:** the kernel NBD driver accepts any socket with
a real `shutdown` op, which `AF_UNIX` stream sockets have, so `AF_UNIX`
should work. If it does not, the fallback is a `127.0.0.1` TCP socket on an
ephemeral port inside a dedicated network namespace, which is strictly
worse (the memory-pressure deadlock story below gets harder), and the choice
will be reported honestly rather than quietly.

### 13.3 I/O path

- `NBD_CMD_READ` → map `[off, off+len)` to chunks (§5.4), serve from the
  cache, else read `clen` bytes at `chunk_data_offset + coff` from the
  payload partition, decompress into a `ulen` buffer, **BLAKE3 the result
  and compare to the chunk hash**, then insert into the cache.
- On hash mismatch, on short read, or on decompression failure: reply
  `NBD_REP_` error `EIO` for that request, log once per distinct chunk
  index, and **do not cache the bad data**. Never return unverified bytes.
  An I/O error is the correct outcome; silently wrong data is not.
- `NBD_CMD_WRITE`, `NBD_CMD_TRIM`, `NBD_CMD_WRITE_ZEROES` → `EPERM`.
- `NBD_CMD_FLUSH` → success (nothing to flush).
- `NBD_CMD_DISC` → stop serving, exit after the device is gone.
- Cache: fixed-capacity LRU keyed by chunk index, byte-budgeted
  (`rd.nsif.cache=`, default 192 MiB), with all buffers **preallocated at
  startup** into a slab so the I/O path performs no heap allocation.

### 13.4 Surviving memory pressure — the deadlock

The failure mode: the daemon serving the root filesystem needs memory to
serve a read; the kernel tries to free memory by reclaiming page cache;
reclaim needs to write back or re-read pages that live on the filesystem
the daemon serves; the daemon is waiting for memory. Nothing moves.

Mitigations, all required:

1. **`prctl(PR_SET_IO_FLUSHER, 1)`** immediately at startup. This is the
   kernel's purpose-built answer: it marks the task `PF_MEMALLOC_NOIO`, so
   allocations it makes cannot recurse into the block layer or filesystem,
   and it gets access to a reclaim-independent reserve. Linux ≥ 5.6.
2. **The binary must not live on the filesystem it serves.** Its text pages
   are file-backed; a page fault on `nsif-boot`'s own code would require I/O
   from `nsif-boot`. At startup, `nsif-boot` copies itself to
   `/run/nsif/nsif-boot` (tmpfs, which survives `switch_root`) and
   `execve`s that copy. The original initramfs copy is then irrelevant.
3. **`mlockall(MCL_CURRENT | MCL_FUTURE)`** after the re-exec and after the
   cache slab is allocated, so neither code nor cache can be evicted.
   Failure to mlock is a warning, not fatal, but is reported.
4. **No allocation in the I/O path.** Slab-allocated buffers, no `Vec`
   growth, no formatting into owned strings on the hot path.
5. **`oom_score_adj = -1000`** written to `/proc/self/oom_score_adj`. The
   OOM killer must never choose the process that owns the root filesystem;
   killing it turns a recoverable OOM into an unrecoverable one.
6. **Fixed-size, bounded cache.** The daemon's RSS has a ceiling known at
   startup: slab + code + stack. It never grows under load.
7. Single-threaded I/O loop on `epoll` (no thread pool whose stacks could
   fault), with the socket set non-blocking and replies written from the
   same preallocated buffers.

### 13.5 Surviving `switch_root` and shutdown

systemd's rules for storage daemons started in the initrd (see systemd's
`INITRD_INTERFACE` and "Storage Daemons in the initrd"):

1. **`argv[0]` MUST begin with `@`.** systemd's initrd cleanup and
   `systemd-shutdown` both skip processes whose `argv[0]` starts with `@`.
   `nsif-boot` re-execs itself with `argv[0] = "@/run/nsif/nsif-boot"`.
   Without this, the daemon is killed during the transition and the root
   filesystem vanishes mid-boot.
2. The binary and every file it has open MUST be outside the initramfs root
   that `switch_root` deletes, and outside `/sysroot`. `/run` is a tmpfs
   that is moved, not destroyed, across `switch_root`, so everything lives
   in `/run/nsif/`.
3. `chdir("/")` and close every inherited fd except the ones it needs, so it
   pins nothing in the old root.
4. Open the payload partition by **`O_RDONLY` fd held open from the start**;
   never re-open by path after `switch_root`, because `/dev` may be
   remounted and device names are not guaranteed stable.
5. **Shutdown.** systemd pivots into `/run/initramfs` for the final
   teardown if that directory contains a usable root. `nsif-boot`
   populates `/run/initramfs` with a minimal tree (itself, `busybox`, the
   shutdown binary) so the daemon is still there to serve reads while
   `/sysroot` is unmounted. With the `@` prefix it is not killed, and it
   exits on its own after `NBD_CMD_DISC` or after the device's last
   reference is dropped.
6. A watchdog: if the NBD device disappears and no `DISC` arrived,
   `nsif-boot` waits 30 s and exits, rather than lingering forever.
7. `nsif-boot` writes its state (device path, chunk count, cache size, pid)
   to `/run/nsif/state.json` so the booted system can introspect it, and a
   `nsif-boot.service` unit in the rootfs can own it via
   `PIDFile=/run/nsif/nsif-boot.pid` with `KillMode=none`.

---

## 14. Interoperability notes

- A `.nsif` is a GPT disk image. `fdisk -l`, `parted`, `gdisk`,
  `blkid` and the Linux kernel all read it as a disk with two partitions.
- Writing it with `dd`, `cp` to a block device, Rufus in DD mode, Etcher,
  `gnome-disks` "Restore Disk Image", or Windows' `diskpart`-plus-raw-writer
  all work, because there is nothing to interpret.
- The file extension is cosmetic. `.nsif` carries no meaning to any
  bootloader or firmware. It exists so humans and `file(1)` magic can tell
  the thing apart from an ISO. See the README for Rufus specifics.
- Suggested `file(1)` magic: offset of partition 2's first sector is not
  fixed, so match on the GPT partition type GUID instead; a simple rule is
  `0x200` = `"EFI PART"` plus the payload type GUID anywhere in the first
  34 sectors.

---

## 15. Changes that require a format version bump

For the avoidance of doubt, all of the following are breaking and MUST NOT
be done inside `0.1`: changing `header_len`; changing any field offset in
§4.1 or §7; adding a required manifest key; changing the signed message
construction in §7.1; changing the GUIDs in §3.3; changing the CBOR
determinism profile; changing the meaning of `coff`/`uoff`.

Non-breaking: adding a codec id; adding optional `metadata` keys; adding
files to the ESP; changing chunking parameters (they are recorded in the
manifest); changing zstd level.
