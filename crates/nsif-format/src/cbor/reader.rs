//! Strict CBOR reader (SPEC §5.1).
//!
//! Enforces, at the byte level and before any value reaches the caller:
//! definite lengths only, shortest-form heads, no floats, no tags, no simple
//! values other than `true`/`false`, valid UTF-8, bytewise-sorted map keys, no
//! duplicate keys, a nesting-depth cap, and no trailing bytes. A manifest that
//! parses but violates any of these is rejected, which is what makes
//! "re-encode and compare bytes" a meaningful test.

use crate::error::{CborError, Result};
use crate::limits::MAX_CBOR_DEPTH;

use super::writer::{MAJOR_ARRAY, MAJOR_BSTR, MAJOR_MAP, MAJOR_SIMPLE, MAJOR_TSTR, MAJOR_UINT};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: u32,
}

/// A decoded head: major type plus its argument.
struct Head {
    major: u8,
    arg: u64,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, depth: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Call after reading the single top-level item (SPEC §5.1.8).
    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(CborError::TrailingBytes { count: self.buf.len() - self.pos }.into());
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(CborError::Truncated { at: self.pos, need: n - self.remaining() }.into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read one head, enforcing shortest form and rejecting indefinite lengths
    /// and reserved additional-information values.
    fn head(&mut self) -> Result<Head> {
        let at = self.pos;
        let b = self.take(1)?[0];
        let major = b >> 5;
        let ai = b & 0x1F;

        // Major type 1 is a negative integer. No field in the v0 schema is
        // signed, so it is rejected here rather than deeper in, which keeps the
        // set of major types the rest of this file has to reason about at
        // {0, 2, 3, 4, 5} plus the booleans.
        if major == 1 {
            return Err(CborError::NegativeIntNotAllowed { at }.into());
        }

        // Majors 6 and 7 are handled before the shortest-form rule, because for
        // them the trailing bytes are a tag number or a float payload, not an
        // integer argument, and the shortest-form rule does not apply.
        if major == 6 {
            return Err(CborError::TagNotAllowed { at }.into());
        }
        if major == 7 {
            return match ai {
                20 | 21 => Ok(Head { major, arg: u64::from(ai) }),
                25..=27 => Err(CborError::FloatNotAllowed { at }.into()),
                28..=30 => Err(CborError::ReservedAdditionalInfo { at, ai }.into()),
                31 => Err(CborError::IndefiniteLength { at }.into()),
                _ => Err(CborError::SimpleNotAllowed { at, value: ai }.into()),
            };
        }

        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return Err(CborError::NonShortestForm { at, value: v, used: 1 }.into());
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([s[0], s[1]]));
                if v <= 0xFF {
                    return Err(CborError::NonShortestForm { at, value: v, used: 2 }.into());
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]]));
                if v <= 0xFFFF {
                    return Err(CborError::NonShortestForm { at, value: v, used: 4 }.into());
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                if v <= 0xFFFF_FFFF {
                    return Err(CborError::NonShortestForm { at, value: v, used: 8 }.into());
                }
                v
            }
            28..=30 => return Err(CborError::ReservedAdditionalInfo { at, ai }.into()),
            31 => return Err(CborError::IndefiniteLength { at }.into()),
            _ => unreachable!("ai is 5 bits"),
        };

        Ok(Head { major, arg })
    }

    fn expect(&mut self, major: u8, name: &'static str) -> Result<u64> {
        let at = self.pos;
        let h = self.head()?;
        if h.major != major {
            return Err(
                CborError::UnexpectedMajor { at, found: h.major, expected: name }.into()
            );
        }
        Ok(h.arg)
    }

    /// Reject a declared length that cannot possibly fit in the remaining input,
    /// before any allocation is attempted.
    fn check_len(&self, at: usize, len: u64) -> Result<usize> {
        if len > self.remaining() as u64 {
            return Err(CborError::LengthBeyondInput { at, len, remaining: self.remaining() }.into());
        }
        Ok(len as usize)
    }

    /// The major type of the next item, without consuming anything. Used where
    /// a value may legitimately be one of several types (`codec_params`).
    pub fn peek_major(&self) -> Result<u8> {
        if self.remaining() == 0 {
            return Err(CborError::Truncated { at: self.pos, need: 1 }.into());
        }
        Ok(self.buf[self.pos] >> 5)
    }

    pub fn uint(&mut self) -> Result<u64> {
        self.expect(MAJOR_UINT, "unsigned integer")
    }

    /// An unsigned integer that must fit in `usize` on this platform.
    pub fn uint_as_usize(&mut self) -> Result<usize> {
        let at = self.pos;
        let v = self.uint()?;
        usize::try_from(v).map_err(|_| CborError::IntegerTooLarge { at, value: v }.into())
    }

    pub fn boolean(&mut self) -> Result<bool> {
        let at = self.pos;
        let h = self.head()?;
        if h.major != MAJOR_SIMPLE {
            return Err(CborError::UnexpectedMajor { at, found: h.major, expected: "boolean" }.into());
        }
        Ok(h.arg == 21)
    }

    pub fn bstr(&mut self) -> Result<&'a [u8]> {
        let at = self.pos;
        let n = self.expect(MAJOR_BSTR, "byte string")?;
        let n = self.check_len(at, n)?;
        self.take(n)
    }

    /// A byte string of exactly `N` bytes, for the 32-byte BLAKE3 hashes.
    pub fn bstr_exact<const N: usize>(&mut self) -> Result<[u8; N]> {
        let at = self.pos;
        let b = self.bstr()?;
        if b.len() != N {
            return Err(CborError::WrongByteStringLength { at, found: b.len(), expected: N }.into());
        }
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn tstr(&mut self) -> Result<&'a str> {
        let at = self.pos;
        let n = self.expect(MAJOR_TSTR, "text string")?;
        let n = self.check_len(at, n)?;
        let b = self.take(n)?;
        core::str::from_utf8(b).map_err(|_| CborError::InvalidUtf8 { at }.into())
    }

    /// Read an array head and return its item count.
    pub fn array_header(&mut self) -> Result<usize> {
        let at = self.pos;
        let n = self.expect(MAJOR_ARRAY, "array")?;
        // An array item is at least one byte, so a count beyond the remaining
        // input is impossible and must not drive an allocation.
        self.check_len(at, n)?;
        Ok(n as usize)
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_CBOR_DEPTH {
            return Err(CborError::DepthExceeded { at: self.pos, max: MAX_CBOR_DEPTH }.into());
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    /// Read a definite-length array, calling `f` once per item.
    pub fn array<T, F>(&mut self, mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(&mut Reader<'a>) -> Result<T>,
    {
        let n = self.array_header()?;
        self.enter()?;
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            out.push(f(self)?);
        }
        self.leave();
        Ok(out)
    }

    /// Read a definite-length map with text-string keys, enforcing bytewise key
    /// ordering and rejecting duplicates. `f` is called with each key.
    pub fn map<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Reader<'a>, &'a str) -> Result<()>,
    {
        let at = self.pos;
        let n = self.expect(MAJOR_MAP, "map")?;
        self.check_len(at, n)?;
        self.enter()?;
        let mut prev: Option<&'a [u8]> = None;
        for _ in 0..n {
            let key_start = self.pos;
            let key = self.tstr()?;
            let key_enc = &self.buf[key_start..self.pos];
            if let Some(p) = prev {
                match key_enc.cmp(p) {
                    core::cmp::Ordering::Greater => {}
                    core::cmp::Ordering::Equal => {
                        return Err(CborError::DuplicateMapKey {
                            at: key_start,
                            key: key.to_owned(),
                        }
                        .into())
                    }
                    core::cmp::Ordering::Less => {
                        return Err(CborError::MapKeysUnsorted {
                            at: key_start,
                            earlier: String::from_utf8_lossy(&p[1..]).into_owned(),
                            later: key.to_owned(),
                        }
                        .into())
                    }
                }
            }
            prev = Some(key_enc);
            f(self, key)?;
        }
        self.leave();
        Ok(())
    }

    /// Read a map and return its entry count without consuming entries; used
    /// where a count cap must be checked before iterating.
    pub fn map_header(&mut self) -> Result<usize> {
        let at = self.pos;
        let n = self.expect(MAJOR_MAP, "map")?;
        self.check_len(at, n)?;
        Ok(n as usize)
    }
}

/// One open container during the generic profile walk.
enum Frame<'a> {
    Array { left: u64 },
    Map { pairs_left: u64, expecting_key: bool, prev_key: Option<&'a [u8]> },
}

/// Validate a byte string against the whole deterministic profile of
/// SPEC §5.1, independently of any schema.
///
/// `Manifest::decode` runs this first, so profile violations are reported as
/// profile violations rather than as whatever schema error they happen to
/// trigger. The walk is iterative with an explicit stack, so a deeply nested
/// input cannot overflow our own stack even before the depth cap applies.
pub fn validate_profile(buf: &[u8]) -> Result<()> {
    let mut r = Reader::new(buf);
    let mut stack: Vec<Frame<'_>> = Vec::new();

    'items: loop {
        let expecting_key = matches!(
            stack.last(),
            Some(Frame::Map { expecting_key: true, .. })
        );

        let at = r.pos;
        let h = r.head()?;

        if expecting_key && h.major != MAJOR_TSTR {
            return Err(CborError::UnexpectedMajor {
                at,
                found: h.major,
                expected: "text string (map keys must be text strings)",
            }
            .into());
        }

        let mut pushed = false;
        match h.major {
            MAJOR_UINT => {}
            MAJOR_BSTR => {
                let n = r.check_len(at, h.arg)?;
                r.take(n)?;
            }
            MAJOR_TSTR => {
                let key_start = at;
                let n = r.check_len(at, h.arg)?;
                let b = r.take(n)?;
                core::str::from_utf8(b).map_err(|_| CborError::InvalidUtf8 { at })?;
                if expecting_key {
                    let key_enc = &buf[key_start..r.pos];
                    if let Some(Frame::Map { prev_key, .. }) = stack.last_mut() {
                        if let Some(p) = *prev_key {
                            match key_enc.cmp(p) {
                                core::cmp::Ordering::Greater => {}
                                core::cmp::Ordering::Equal => {
                                    return Err(CborError::DuplicateMapKey {
                                        at: key_start,
                                        key: String::from_utf8_lossy(b).into_owned(),
                                    }
                                    .into())
                                }
                                core::cmp::Ordering::Less => {
                                    return Err(CborError::MapKeysUnsorted {
                                        at: key_start,
                                        earlier: String::from_utf8_lossy(&p[1..]).into_owned(),
                                        later: String::from_utf8_lossy(b).into_owned(),
                                    }
                                    .into())
                                }
                            }
                        }
                        *prev_key = Some(key_enc);
                    }
                }
            }
            MAJOR_ARRAY | MAJOR_MAP => {
                r.check_len(at, h.arg)?;
                if h.arg != 0 {
                    if stack.len() as u32 + 1 > MAX_CBOR_DEPTH {
                        return Err(CborError::DepthExceeded { at, max: MAX_CBOR_DEPTH }.into());
                    }
                    stack.push(if h.major == MAJOR_ARRAY {
                        Frame::Array { left: h.arg }
                    } else {
                        Frame::Map { pairs_left: h.arg, expecting_key: true, prev_key: None }
                    });
                    pushed = true;
                }
            }
            MAJOR_SIMPLE => {} // head() already restricted this to true/false
            other => {
                // Unreachable today: head() rejects majors 1, 6 and non-boolean
                // 7. Kept as an error rather than `unreachable!` so that
                // widening the accepted set can never become a panic on
                // attacker-supplied bytes.
                return Err(CborError::UnexpectedMajor {
                    at,
                    found: other,
                    expected: "uint, byte string, text string, array, map or boolean",
                }
                .into());
            }
        }

        if pushed {
            continue 'items;
        }

        // The item just read is complete. Account for it in its parent, popping
        // any container that is now finished.
        loop {
            match stack.last_mut() {
                None => break 'items,
                Some(Frame::Array { left }) => {
                    *left -= 1;
                    if *left == 0 {
                        stack.pop();
                        continue;
                    }
                    break;
                }
                Some(Frame::Map { pairs_left, expecting_key, prev_key: _ }) => {
                    if *expecting_key {
                        // we just read the key; the value comes next
                        *expecting_key = false;
                        break;
                    }
                    *pairs_left -= 1;
                    *expecting_key = true;
                    if *pairs_left == 0 {
                        stack.pop();
                        continue;
                    }
                    break;
                }
            }
        }
    }

    r.finish()
}
