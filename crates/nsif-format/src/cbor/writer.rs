//! Deterministic CBOR writer (SPEC §5.1).
//!
//! The writer can only emit conforming output: heads are always shortest-form,
//! lengths are always definite, and maps are buffered and sorted by encoded key
//! bytes on `finish`, so no caller can produce an unsorted map by accident.
//! There is deliberately no API for floats, tags or indefinite lengths.

use crate::error::{Error, Result};

pub const MAJOR_UINT: u8 = 0;
pub const MAJOR_BSTR: u8 = 2;
pub const MAJOR_TSTR: u8 = 3;
pub const MAJOR_ARRAY: u8 = 4;
pub const MAJOR_MAP: u8 = 5;
pub const MAJOR_SIMPLE: u8 = 7;

#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self { buf: Vec::with_capacity(n) }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Emit a head in the shortest form that can carry `arg` (SPEC §5.1.2).
    pub fn head(&mut self, major: u8, arg: u64) {
        debug_assert!(major <= 7);
        let m = major << 5;
        match arg {
            0..=23 => self.buf.push(m | arg as u8),
            24..=0xFF => {
                self.buf.push(m | 24);
                self.buf.push(arg as u8);
            }
            0x100..=0xFFFF => {
                self.buf.push(m | 25);
                self.buf.extend_from_slice(&(arg as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.buf.push(m | 26);
                self.buf.extend_from_slice(&(arg as u32).to_be_bytes());
            }
            _ => {
                self.buf.push(m | 27);
                self.buf.extend_from_slice(&arg.to_be_bytes());
            }
        }
    }

    pub fn uint(&mut self, v: u64) {
        self.head(MAJOR_UINT, v);
    }

    pub fn bstr(&mut self, b: &[u8]) {
        self.head(MAJOR_BSTR, b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn tstr(&mut self, s: &str) {
        self.head(MAJOR_TSTR, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn boolean(&mut self, b: bool) {
        self.buf.push((MAJOR_SIMPLE << 5) | if b { 21 } else { 20 });
    }

    /// Begin a definite-length array of exactly `n` items; the caller writes them.
    pub fn array(&mut self, n: usize) {
        self.head(MAJOR_ARRAY, n as u64);
    }

    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}

/// Buffers map entries and emits them sorted by encoded key bytes, which is
/// precisely the rule in SPEC §5.1.3. Duplicate keys are rejected rather than
/// silently collapsed (SPEC §5.1.4).
#[derive(Default, Debug)]
pub struct MapWriter {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MapWriter {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add an entry whose key is a text string.
    pub fn entry<F>(&mut self, key: &str, write_value: F)
    where
        F: FnOnce(&mut Writer),
    {
        let mut kw = Writer::new();
        kw.tstr(key);
        let mut vw = Writer::new();
        write_value(&mut vw);
        self.entries.push((kw.into_bytes(), vw.into_bytes()));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sort by encoded key bytes, reject duplicates, and append to `out`.
    pub fn finish(mut self, out: &mut Writer) -> Result<()> {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        for w in self.entries.windows(2) {
            if w[0].0 == w[1].0 {
                // Keys are text strings here, so this decodes cleanly.
                let name = String::from_utf8_lossy(&w[0].0[1..]).into_owned();
                return Err(Error::BadField {
                    field: "<map>",
                    problem: format!("duplicate key {name:?}"),
                });
            }
        }
        out.head(MAJOR_MAP, self.entries.len() as u64);
        for (k, v) in self.entries {
            out.raw(&k);
            out.raw(&v);
        }
        Ok(())
    }
}

/// Compare two text-string map keys the way SPEC §5.1.3 does: by the bytes of
/// their CBOR encoding, which orders primarily by length for keys under 24
/// bytes. Exposed so other crates can keep sorted orders consistent.
pub fn key_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let mut wa = Writer::new();
    wa.tstr(a);
    let mut wb = Writer::new();
    wb.tstr(b);
    wa.into_bytes().cmp(&wb.into_bytes())
}
