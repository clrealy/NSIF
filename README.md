# NSIF — No Shit Installer File

A replacement for `.iso` for booting and installing Linux, built around one
hard constraint:

> **A `.nsif` file is a valid GPT disk image.** `dd if=x.nsif of=/dev/sdX`
> gives you a bootable disk. There is no special tooling, no hybrid MBR, no
> El Torito, and no ISO 9660.

Everything else — the compressed payload, the content-defined chunking, the
delta updates, the signature — is built on top of that without breaking it.

**Status: v0 in development.** The format is specified in
[`SPEC.md`](SPEC.md) and the build plan in [`PLAN.md`](PLAN.md). Release
codename: **Hammer**.

## What it does

- **Flashable raw.** GPT with 512-byte sectors, a FAT32 ESP, and an NSIF
  payload partition with its own type GUID.
- **Self-describing.** A binary header points at a signed manifest listing
  the BLAKE3 hash of every ESP file and every payload chunk.
- **Compressed.** zstd by default, behind a `Codec` trait.
- **Verifiable.** `nsif verify --pubkey <key>` checks the signature, every
  chunk, and every ESP file.
- **Delta-updatable.** FastCDC content-defined chunking means a small rootfs
  change touches few chunks; `nsif update` fetches only those, over HTTP
  range requests.
- **Persistent.** On first boot a persistence partition is created from the
  unused tail of the disk, and the rootfs is mounted as an overlay on it. The
  ESP and payload are never modified.
- **Reproducible.** The same inputs and the same `--build-date` produce a
  byte-identical file. `nsif pack` builds the GPT, the FAT32 and the payload
  in userspace: no root, no loop devices, no mounting.

## Scope of v0

UEFI x86_64 only. 512-byte logical sectors only. No legacy BIOS, no El
Torito, no ISO 9660, no 4Kn media.

## Trust model — please read this

**Secure Boot is out of scope for v0, and that has a consequence that must
not be glossed over.**

The ESP is unsigned. `BOOTX64.EFI`, the kernel, the initramfs and the
`nsif-boot` helper are all plain files on a FAT32 partition. Anyone who can
write to the media can replace `nsif-boot` with something that skips every
check, or replace the kernel outright.

**Therefore the hash verification that happens at boot detects corruption,
not tampering.** It catches a bad flash, a dying USB stick, bit rot, a
truncated download. It does not catch an adversary, and describing it as a
security guarantee would be false.

The Ed25519 signature is meaningful only when checked by `nsif verify` or
`nsif update` on a machine you trust, with a key you obtained out of band. In
that setting it does authenticate the manifest, and through the manifest's
hashes, the rootfs and the ESP files.

Related: **the public key stored inside a `.nsif` proves nothing about who
published it.** Anyone can generate a key, sign a manifest, and embed the
matching public key. `nsif verify` and `nsif update` therefore require a key
from `--pubkey` or a trusted keyring and never fall back to the embedded one.
`nsif info` prints the embedded key's fingerprint marked unverified, purely
so you can tell which key you would need.

See [`SPEC.md`](SPEC.md) §12 for the full statement and what v1 is expected
to do about it.

## Repository layout

| Path | Contents |
|---|---|
| `SPEC.md` | The on-disk format, precisely enough to write a second implementation |
| `PLAN.md` | Crate layout, the NBD-vs-ublk decision, milestones, environment limits |
| `crates/nsif-format` | Header, manifest, validation, codecs, chunking, signatures. No I/O. |
| `fuzz/` | `cargo-fuzz` targets for the header, manifest and payload parsers |

## Development

```sh
cargo test                      # the whole suite
cargo test --test reject        # the rejection suite only
cargo clippy --all-targets
```

Fuzzing needs a nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
# regenerate the seed corpus (checked in, but cheap to rebuild)
cargo test -p nsif-format --test corpus -- --ignored --nocapture
cargo +nightly fuzz run fuzz_header   -- -max_total_time=300
cargo +nightly fuzz run fuzz_manifest -- -max_total_time=300
cargo +nightly fuzz run fuzz_payload  -- -max_total_time=300
```

`cargo test` also runs a deterministic no-panic sweep over the same entry
points (`parsers_never_panic_on_arbitrary_input`), so the contract is checked
on a stable toolchain too.

### A note on `nsif flash`

`nsif flash` is not implemented yet. When it is, it will refuse mounted disks
and non-removable disks unless `--force` is passed, and will require typed
confirmation after showing the device model and size. **It is never run
against a real device during development of this repository** — only against
image files and loop devices.

## Licence

MIT. See [`LICENSE`](LICENSE).
