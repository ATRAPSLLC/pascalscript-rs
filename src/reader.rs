//! Internal LE-safe byte cursor for the
//! [`pascal_script`](crate) parser.
//!
//! Mirrors the shape of [`crate::util::read::Reader`] but is kept
//! private to this module so the eventual standalone-crate split
//! has no `crate::util` dependency to unwind.

use crate::error::Error;

/// Cursor over a borrowed byte buffer with truncation-aware reads.
///
/// All multi-byte reads are little-endian to match the upstream
/// PascalScript on-disk format.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

// The full Reader surface (u8/u32_le/i32_le/array/take/skip plus
// pos/len/buf accessors) is used across the type/proc/var/operand
// walkers; module-wide allow keeps the per-method noise out of
// the deny-set.
#[allow(dead_code)]
impl<'a> Reader<'a> {
    /// Wraps `buf` with the cursor at offset 0.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the current cursor position (0-based byte offset).
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the total length of the underlying buffer.
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns the underlying buffer slice from the start.
    pub(crate) fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Advances the cursor by `n` bytes, surfacing
    /// [`Error::Truncated`] when the requested span runs past
    /// end-of-buffer.
    pub(crate) fn skip(&mut self, n: usize, what: &'static str) -> Result<(), Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        if new_pos > self.buf.len() {
            return Err(Error::Truncated { what });
        }
        self.pos = new_pos;
        Ok(())
    }

    /// Reads `n` bytes from the current position and advances.
    pub(crate) fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        let slice = self
            .buf
            .get(self.pos..new_pos)
            .ok_or(Error::Truncated { what })?;
        self.pos = new_pos;
        Ok(slice)
    }

    /// Reads one byte.
    pub(crate) fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        let slice = self.take(1, what)?;
        let byte = slice.first().copied().ok_or(Error::Truncated { what })?;
        Ok(byte)
    }

    /// Reads a 4-byte little-endian unsigned integer.
    pub(crate) fn u32_le(&mut self, what: &'static str) -> Result<u32, Error> {
        let slice = self.take(4, what)?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| Error::Truncated { what })?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Reads a 4-byte little-endian signed integer.
    pub(crate) fn i32_le(&mut self, what: &'static str) -> Result<i32, Error> {
        let slice = self.take(4, what)?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| Error::Truncated { what })?;
        Ok(i32::from_le_bytes(arr))
    }

    /// Reads a fixed-size byte array.
    pub(crate) fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Error> {
        let slice = self.take(N, what)?;
        let arr: [u8; N] = slice.try_into().map_err(|_| Error::Truncated { what })?;
        Ok(arr)
    }
}
