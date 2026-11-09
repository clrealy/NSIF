# NSIF v0 — plan

Companion to `SPEC.md`. Read `SPEC.md` for the format; this file is the
build order, the two contested decisions, and what this sandbox can and
cannot test.

---

## 1. Shape of the thing

One Cargo workspace, four crates:

| Crate | Kind | Purpose |
|---|---|---|
| `nsif-format` | lib, `no_std`-friendly core | Header + manifest structs, deterministic CBOR codec, all validation, `Codec` trait, FastCDC wrapper, GUID derivation. No I/O. This is the crate a second implementation would be checked against. |
| `nsif-image` | lib | GPT writer/reader, deterministic FAT32 writer, payload assembler, chunk store reader. Pure userspace: `pwrite` into a file, no root, no loop, no mount. |
| `nsif` | bin | The CLI: `pack`, `info`, `verify`, `diff`, `update`, `flash`, `keygen`. |
| `nsif-boot` | bin, `x86_64-unknown-linux-musl` static | The initramfs daemon: find payload, verify, serve NBD, overlay, persistence, survive `switch_root`. |

Plus `fuzz/` with `cargo-fuzz` targets, and `tests/` with the integration
and QEMU end-to-end harnesses.

Dependencies, all confirmed resolvable and compiling in this sandbox:
`blake3`, `zstd`, `ed25519-dalek` 3.0, `fastcdc` 5.0, `ciborium` (CBOR —
used for reading; the deterministic *writer* is ours, because no
general-purpose library guarantees the profile in SPEC §5.1),
`crc32c`, `crc32fast`, `fatfs` 0.3, `rustix`, `neli` (generic netlink for
NBD), `clap`, `reqwest` (HTTP range requests), `arbitrary` + `proptest` for
tests.

---

## 2. Decision: NBD for v0, ublk behind the same trait for v1

**Recommendation: NBD.** Both backends sit behind one trait so this is
reversible without touching the format:

```rust
trait BlockBackend {
    fn attach(&mut self, size: u64, reader: Arc<dyn ChunkReader>) -> Result<PathBuf>;
    fn serve(&mut self) -> Result<()>;   // runs until DISC / detach
    fn detach(&mut self) -> Result<()>;
}
```

### The case for ublk

- Purpose-built for exactly this: a userspace block device driver, no
  network stack in the path, `io_uring` command queue, shared memory for
  the data, measurably lower per-I/O overhead than NBD's socket round trip.
- `UBLK_F_USER_RECOVERY` / `UBLK_F_USER_RECOVERY_REISSUE` give a real,
  documented story for "the daemon died, reattach a new one" — NBD's
  equivalent (`NBD_CMD_RECONFIGURE` with a fresh socket) is clumsier.
- Zero-copy support (`UBLK_F_SUPPORT_ZERO_COPY`, usable from 6.12) removes
  a memcpy per I/O.
- No socket, so no "can a kernel block device safely talk to a userspace
  daemon over a socket under memory pressure" question at all.

### The case for NBD, which wins

1. **Kernel availability, and it is not close.** `CONFIG_BLK_DEV_NBD` has
   been in mainline since 2.1.55 and is enabled, as a module, in
   essentially every distribution kernel shipping today.
   `CONFIG_BLK_DEV_UBLK` only landed in **6.0** (Aug 2022) and is *not*
   enabled everywhere. Measured in this sandbox, not recalled: Ubuntu
   24.04's `linux-image-virtual` 6.8.0-149 ships
   `kernel/drivers/block/nbd.ko.zst` and **ships no `ublk_drv` module at
   all**. That is a current LTS distribution.

2. **This is a format for other people's kernels.** A `.nsif` carries the
   kernel in its own ESP, so the kernel is chosen by whoever runs
   `nsif pack` — Debian, Ubuntu, Fedora, Alpine, a vendor appliance team.
   Requiring ublk means telling every one of them "rebuild your kernel with
   a new config option before you can ship a `.nsif`". That is a much
   bigger ask than it looks and it would be the single largest barrier to
   anyone adopting the format. Requiring NBD asks nothing of anyone. For a
   v0 whose job is to prove the idea, adoption cost beats microseconds per
   I/O.

3. **The performance gap does not bind here.** The device is read-only,
   backed by zstd-compressed chunks that must be decompressed and
   BLAKE3-verified on every cache miss. Decompression of a 64 KiB chunk
   costs on the order of 50–150 µs; a BLAKE3 hash of it costs ~20 µs. NBD's
   socket round trip is a few microseconds. The transport is nowhere near
   the bottleneck — the codec is. Optimising the transport first would be
   optimising the wrong end.

4. **`AF_UNIX`, not TCP, removes NBD's worst reputation.** The classic NBD
   complaints — loopback TCP, memory-pressure writeback deadlock, network
   namespaces, `nbd-client` as a separate process — all come from using it
   the usual way. `nsif-boot` is server *and* configurator in one process:
   it creates an `AF_UNIX` `socketpair`, hands one end to the kernel via
   generic netlink `NBD_CMD_CONNECT`, and serves the other end itself.
   There is no TCP, no port, no loopback interface, no `nbd-client`, and
   nothing for a network namespace to interfere with. And because the
   device is **read-only**, the canonical NBD deadlock (dirty page writeback
   needing the network stack) cannot arise: there is no writeback to this
   device. Writes go to the persistence partition, which is a real
   virtio/NVMe/USB device that does not involve `nsif-boot` at all.

5. **Switch_root behaviour is identical for both.** Neither backend changes
   the hard part. In both cases the kernel holds a reference to a userspace
   daemon that must survive `switch_root`, dodge the OOM killer, and not
   deadlock during reclaim. The required measures are the same — `argv[0]`
   prefixed with `@` so systemd's initrd cleanup and `systemd-shutdown`
   skip it, re-exec from `/run` (tmpfs survives `switch_root`; the
   initramfs root does not), `PR_SET_IO_FLUSHER`, `mlockall`,
   `oom_score_adj=-1000`, a preallocated bounded cache, `/run/initramfs`
   populated for shutdown. SPEC §13.4 and §13.5 specify all of it. Choosing
   ublk would buy nothing here; choosing NBD costs nothing here.

   One genuine ublk-specific hazard that NBD avoids: a ublk device is bound
   to the task that created it, and the `io_uring` ring is per-queue and
   owned by a specific thread. Keeping that ownership intact across a
   `switch_root` and a re-exec is strictly more delicate than keeping a
   socket fd open. NBD only needs the fd.

6. **Honest downside of NBD, stated:** `nbds_max` is a module parameter, so
   the device count is fixed at `modprobe` time; `/dev/nbdN` names are not
   as self-describing as `/dev/ublkbN`; and NBD has no equivalent of
   `UBLK_F_USER_RECOVERY`, so if `nsif-boot` dies the root filesystem is
   gone and the machine is finished. The mitigation is prevention
   (SPEC §13.4) rather than recovery, which is the right trade for v0 but is
   a real limitation and is why ublk stays on the roadmap.

### Kernel requirements, restated

- **v0 / NBD:** `CONFIG_BLK_DEV_NBD`, `CONFIG_OVERLAY_FS`,
  `CONFIG_EFI_PARTITION`, `CONFIG_TMPFS`, a filesystem matching
  `rootfs_fstype` (`CONFIG_EROFS_FS` by default), and
  `PR_SET_IO_FLUSHER` (**Linux ≥ 5.6**). Practical floor: **5.6**.
- **v1 / ublk:** additionally `CONFIG_BLK_DEV_UBLK` and `CONFIG_IO_URING`,
  **Linux ≥ 6.0**, realistically ≥ 6.2 for a stable `UBLK_F_USER_RECOVERY`,
  ≥ 6.12 for zero-copy.

`nsif-boot` will probe at runtime: try ublk if the module/control device is
present and the backend is compiled in, else NBD, else fail with a message
naming the missing kernel option. The format does not encode the choice.

---

## 3. Manifest: CBOR

Chosen, with the reasoning in SPEC §2: the signature is over manifest
bytes so the encoding must be canonical and JSON has no deployed canonical
form; u64 offsets need native integers; the chunk list is ~3× smaller; and
the parser that runs before anything is verified is much smaller. JSON
remains the `--json` output format for `info` and `diff`.

---

## 4. Milestones

Each one is tested before the next starts, and I report what actually
passed, including the parts that did not.

### M1 — `nsif-format`: the format and nothing else
Workspace, header codec, deterministic CBOR writer + strict reader, every
validation rule in SPEC §4.2 / §5.1 / §5.3, the limits table in §9,
`Codec` trait with `zstd` and `none`, FastCDC wrapper, GUID derivation,
Ed25519 sign/verify with the §7.1 domain-separated message.
**Tests:** round-trip; re-encode-and-compare canonicality; a table-driven
rejection suite (bad magic, bad CRC, wrong major, truncated manifest,
region overlap, overflowing `off+len`, non-contiguous `uoff`, partial
`coff` overlap, chunk count over cap, `clen` over expansion bound,
indefinite-length CBOR, unsorted map keys, duplicate keys, float present,
depth > 4, trailing bytes); signature verify + tampered-manifest reject.
Two `cargo-fuzz` targets: `fuzz_header`, `fuzz_manifest`.

### M2 — `nsif pack` / `info` / `verify`
GPT writer, deterministic FAT32 writer, payload assembler, chunk store.
**Tests:** `pack` twice with the same inputs → byte-identical (`cmp`);
`sgdisk -v` / `fdisk -l` accept the GPT; the FAT32 is readable by
`mcopy`/`mdir` and by the kernel's FAT driver inside QEMU; `verify`
passes on a good image; `verify` fails correctly on a flipped byte in a
chunk, a flipped byte in an ESP file, a corrupted manifest, a wrong key,
and a truncated file — each with a distinct error.

### M3 — `diff`, `update`, `flash`
FastCDC reuse accounting; `update` fetching manifest + signature first,
verifying before any chunk download, HTTP range requests for missing
chunks, every fetched chunk hash-checked, temp file + `rename` only after
full verification, `version_ordinal` downgrade refusal unless
`--allow-downgrade`. `flash` with the mounted-disk and removable-disk
gates, model/size display, typed confirmation.
**Tests:** one-file change in a rootfs → `diff` reports < 10 % of image
size (and the actual number); a from-scratch rootfs rebuild → the real
reuse number, reported whatever it is; `update` against a local HTTP server
serving byte ranges, including a server that returns a corrupted chunk
(must fail, must leave no partial output) and one that ignores `Range`
(must be detected); downgrade refused; `flash` to an image file and to a
loop device, never to a real disk.

### M4 — `nsif-boot`
Static musl build; payload discovery by type GUID; header + manifest +
hash verification; NBD attach over `AF_UNIX` + netlink; bounded
preallocated chunk cache with per-chunk BLAKE3 verification and `EIO` on
mismatch; overlay mount; persistence creation per SPEC §8; tmpfs fallback;
all of SPEC §13.4 and §13.5.
**Tests:** host-side unit tests of the chunk-reader and the request mapper
against a packed image (no kernel involvement); everything involving a real
NBD device runs inside QEMU, because this sandbox cannot load kernel
modules (§5). This is the milestone where the `AF_UNIX`-socket question in
SPEC §13.2 gets a definite answer.

### M5 — End to end in QEMU/OVMF, and the docs
Raw disk attachment only, no `-kernel`, no extra devices. Boot a packed
image; boot it on a disk larger than the image and confirm persistence is
created, formatted, used, and survives a reboot; flip a byte in a chunk and
confirm the guest gets an I/O error rather than wrong bytes; confirm the
backup GPT relocation leaves partitions 1 and 2 untouched (byte-compare
them before and after). README with the trust-model statement from SPEC §12
verbatim, and the Rufus test procedure for Windows.

---

## 5. What this sandbox can and cannot do

Verified just now, not assumed:

**Available:** Rust 1.97, crates.io, `apt`, `qemu-system-x86_64` 8.2.2,
OVMF (`/usr/share/OVMF/OVMF_CODE_4M.fd`, confirmed to boot and to emit
serial output), `dosfstools`, `mtools`, `busybox-static`, `gcc`,
`/dev/loop0`–`loop1`, root, 4 cores, 16 GB RAM, 31 GB free disk.

**Not available, and the consequences:**

| Missing | Consequence | What I will do |
|---|---|---|
| `/dev/kvm` | QEMU runs under TCG. A boot that takes 5 s with KVM may take 1–3 min. | Keep the E2E rootfs tiny (busybox + mke2fs, ~10 MB). If a test gets impractically slow I will say so rather than drop it. |
| No `/lib/modules`, no `modprobe` in the container; `nbd.ko` cannot be loaded on the host | **No NBD device can be created on the host.** `nsif-boot`'s transport cannot be unit-tested outside a VM. | All real-device NBD testing happens inside QEMU, where the guest kernel is ours. Host tests cover the chunk reader, the offset mapper, and the netlink message encoding in isolation. |
| `ublk_drv` absent from the only kernel package available here | Cannot test a ublk backend at all. | Reinforces the NBD decision; ublk is deferred to v1 rather than written blind. |
| `dl-cdn.alpinelinux.org`, `cdn.kernel.org`, `git.kernel.org` all blocked by the egress proxy (CONNECT denied) | Cannot fetch an Alpine rootfs or build a custom kernel from upstream source. | Guest kernel comes from Ubuntu's `linux-image-virtual` 6.8.0 (has `nbd.ko`, `overlay.ko`, `erofs.ko`); guest rootfs is built from `busybox-static` + `e2fsprogs` from `apt`. Good enough, and honest about what kernel the E2E actually proves. |
| Windows, Rufus | Cannot test Rufus. | Documented procedure for you to run, including the extension question. |
| No real removable device | `flash` cannot be tested against hardware. | Tested against image files and loop devices only. `flash` will never be pointed at a real device during development. |

**Things I expect to have to ask you to run:** anything Rufus, anything on
real USB hardware, and any boot test on a machine with Secure Boot enabled
(which v0 will fail, by design — SPEC §12). Exact commands will come with
M5.

---

## 6. Decisions I am making myself (noted, not asked)

- Workspace layout and crate split above.
- `ciborium` for reading CBOR, hand-written deterministic writer. No
  off-the-shelf writer guarantees SPEC §5.1.
- `fatfs` crate for FAT32 structure, driven deterministically by our own
  insertion order and fixed volume ID, rather than hand-rolling FAT.
- Default rootfs filesystem **EROFS** (small, read-only by design, cheap
  random reads, which suits a chunked backing device better than SquashFS's
  own block compression layering on top of ours). `squashfs` and `ext4`
  remain accepted values in the manifest.
- `mke2fs` shelled out to for the persistence partition rather than
  writing an ext4 formatter. It is a normal initramfs component; absence is
  handled by the tmpfs fallback.
- systemd-boot + a BLS Type #1 entry in v0, rather than a UKI. Plain text
  config files, trivially reproducible, no PE section writing. UKI in v1.
- FastCDC defaults: min 16 KiB, avg 64 KiB, max 256 KiB, normalization 2.
  ~70 bytes of manifest per chunk means ~0.11 % manifest overhead, and
  64 KiB is small enough that a single-file change touches 1–3 chunks.
- Default zstd level 19 for `pack`, with `--level`.
- `pack` requires `--build-date` or `SOURCE_DATE_EPOCH`; it will not
  silently use "now" and produce an unreproducible file.

## 7. Decisions I need from you

These are the on-disk-format items, which is the expensive thing to change
later. Approving `SPEC.md` approves all of them; flag any you want changed.

1. The two assigned partition type GUIDs (SPEC §3.3):
   payload `285621D5-0502-4ECF-9CEE-75F40014C6B3`,
   persistence `9A5B35C3-3C4D-4731-9E97-0936CC569006`.
   A custom persistence GUID rather than the generic Linux-filesystem-data
   GUID, so `nsif-boot` can never adopt an unrelated Linux partition that
   happens to be on the same disk.
2. CBOR for the manifest (SPEC §2).
3. The 4096-byte header layout (SPEC §4.1) and the signed message
   construction `"NSIF-SIG-v1\0" || ver || manifest_len || manifest`
   (SPEC §7.1).
4. Explicit `uoff`/`coff` per chunk, with deduplication expressed as two
   chunks sharing one compressed extent (SPEC §5.3.9).
5. Embedding the signer's public key in the file as *informational only*,
   with `info` printing it marked unverified (SPEC §7.2). The alternative is
   not storing it at all.
6. `version_ordinal` as a separate monotonic integer alongside the display
   `image_version` string, so downgrade detection does not depend on parsing
   version strings.
