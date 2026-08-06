//! `no_std` flash-backed [`DurableStore`]: an A/B two-page ("ping-pong")
//! log over any [`embedded-storage`] [`NorFlash`], for bare-metal nodes that
//! have raw flash rather than a filesystem.
//!
//! Flash has neither atomic rename nor atomic byte-level overwrite, so the
//! file backend's rename trick is unavailable. Each [`DurableStore::save`]
//! instead writes to whichever of two pages does *not* hold the newest valid
//! copy, behind a header carrying a generation counter and a payload CRC32;
//! [`DurableStore::load`] returns the highest-generation page that validates.
//! A write torn by power loss fails CRC, so `load` falls back to the previous
//! intact page — exactly the atomicity `save` promises.
//!
//! Designed in `docs/design/implemented/04-generic-durable-store.md` §3.5.
//!
//! [`embedded-storage`]: https://docs.rs/embedded-storage

use embedded_storage::nor_flash::NorFlash;

use crate::DurableStore;

/// Magic prefixing every page header. Ties a page to *this* format and
/// doubles as a version byte (`WFD1`): a future incompatible layout bumps the
/// trailing digit, and pages written by the old format fail the magic check
/// and read as an empty store rather than being misparsed.
const MAGIC: [u8; 4] = *b"WFD1";

/// Bytes of per-page header preceding the payload: `MAGIC` (4) + generation
/// (4) + payload length (4) + payload CRC32 (4). A multiple of every
/// realistic flash `WRITE_SIZE` (1/2/4/8/16), so the payload that follows it
/// starts write-aligned.
const HEADER_LEN: usize = 16;

/// Upper bound this backend supports for a flash `WRITE_SIZE`, sizing the
/// stack scratch used to pad a payload's sub-word tail. 16 covers every part
/// in view (the nRF52 NVMC is 4); a larger-word flash would fail the
/// compile-time assertion in [`FlashStore::save`].
const MAX_WRITE_SIZE: usize = 16;

/// Chunk size for streaming a page's payload through CRC without buffering the
/// whole blob — keeps header validation allocation-free and bounded regardless
/// of blob size.
const CRC_CHUNK: usize = 64;

/// A [`DurableStore`] backed by two consecutive erase-pages of a [`NorFlash`],
/// alternated on each save so a torn write can only ever damage the copy that
/// wasn't the last good one.
///
/// The two pages live at `base_offset` and `base_offset + page_size`, where
/// `page_size` is the flash's [`NorFlash::ERASE_SIZE`]. `base_offset` must be
/// erase-aligned and both pages must fall inside a region the linker has kept
/// clear of code/data — on the nRF52840 binary that is the top two pages,
/// carved out of the `FLASH` region in `memory.x`.
///
/// The largest blob this store can hold is one page minus [`HEADER_LEN`]; a
/// `save` of anything larger is a [`FlashError::BlobTooLarge`], never a
/// silent spill into the sibling page.
pub struct FlashStore<F> {
    flash: F,
    base_offset: u32,
}

/// A [`FlashStore`] failure: either the underlying flash reported an error, or
/// a blob didn't fit the fixed page geometry.
#[derive(Debug, PartialEq, Eq)]
pub enum FlashError<E> {
    /// The underlying [`NorFlash`] read/erase/write returned an error.
    Flash(E),
    /// A `save` blob exceeds the per-page capacity (one page minus the
    /// header). Carries the offending length and the capacity for the log.
    BlobTooLarge {
        /// The rejected blob's length in bytes.
        len: usize,
        /// The largest blob a page can hold (page size minus header).
        capacity: usize,
    },
    /// A `load` found a stored blob larger than the caller's `out` buffer —
    /// per the [`DurableStore`] contract this is an error, not a truncation.
    BufferTooSmall {
        /// The stored blob's length in bytes.
        len: usize,
        /// The caller-supplied buffer's length in bytes.
        buf: usize,
    },
    /// [`FlashStore::new`]'s `base_offset` wasn't a multiple of the flash's
    /// erase size, so [`FlashStore::page_base`] would address a page
    /// boundary that doesn't exist.
    Unaligned {
        /// The offending offset.
        base_offset: u32,
        /// The flash's erase size — the required alignment.
        erase_size: usize,
    },
    /// The two erase-pages [`FlashStore::new`] needs starting at
    /// `base_offset` don't fit inside the flash device's own reported
    /// capacity — placing the store there would write past the end of the
    /// device (or into a region a misconfigured caller didn't intend).
    OutOfBounds {
        /// The offset one past the last byte the two pages would occupy.
        needed: u32,
        /// The flash device's reported capacity in bytes.
        capacity: usize,
    },
    /// The flash's erase size is too small to hold even this backend's fixed
    /// per-page header, so no page could ever hold a nonempty blob. Rejected
    /// at construction rather than letting [`FlashStore::capacity`] underflow.
    PageTooSmall {
        /// The flash's erase size.
        erase_size: usize,
    },
}

/// A page header parsed and *fully validated* (magic, in-bounds length, and
/// payload CRC all checked) — a torn or never-written page yields `None` from
/// [`FlashStore::read_valid_header`] rather than one of these.
struct PageHeader {
    /// The save generation this page was written at; higher wins.
    generation: u32,
    /// The payload's length in bytes (already checked `<= capacity`).
    len: usize,
}

/// Streaming CRC32 (IEEE 802.3, reflected `0xEDB88320`). Table-free — the
/// blobs here are tens of bytes, so a bytewise loop costs nothing and keeps
/// the backend dependency-free.
struct Crc32(u32);

impl Crc32 {
    fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= b as u32;
            for _ in 0..8 {
                let mask = (self.0 & 1).wrapping_neg();
                self.0 = (self.0 >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    fn finalize(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

impl<F: NorFlash> FlashStore<F> {
    /// A store over the two erase-pages beginning at `base_offset`.
    ///
    /// `base_offset` must be a multiple of the flash's erase size and leave
    /// room for two full pages within the device. Both are real checks, not
    /// `debug_assert!`s: this tracks a linker-script placement, and a release
    /// embedded build would otherwise silently address the wrong region.
    pub fn new(flash: F, base_offset: u32) -> Result<Self, FlashError<F::Error>> {
        let erase_size = F::ERASE_SIZE;
        if erase_size <= HEADER_LEN {
            return Err(FlashError::PageTooSmall { erase_size });
        }
        if !(base_offset as usize).is_multiple_of(erase_size) {
            return Err(FlashError::Unaligned {
                base_offset,
                erase_size,
            });
        }
        let needed = base_offset + 2 * erase_size as u32;
        let capacity = flash.capacity();
        if needed as usize > capacity {
            return Err(FlashError::OutOfBounds { needed, capacity });
        }
        Ok(Self { flash, base_offset })
    }

    /// The largest blob a single page can hold: one erase-page minus the
    /// fixed header.
    pub fn capacity(&self) -> usize {
        F::ERASE_SIZE - HEADER_LEN
    }

    /// Byte offset of page `idx` (0 or 1) within the flash device.
    fn page_base(&self, idx: u32) -> u32 {
        self.base_offset + idx * F::ERASE_SIZE as u32
    }

    /// Read and fully validate page `idx`'s header: `Ok(Some(_))` only if the
    /// magic matches, the recorded length fits a page, and the payload's CRC
    /// matches. A never-written page (erased ⇒ `0xFF` magic) or one left torn
    /// by an interrupted write both fail validation and yield `Ok(None)`;
    /// only an actual flash read error is `Err`.
    fn read_valid_header(&mut self, idx: u32) -> Result<Option<PageHeader>, FlashError<F::Error>> {
        let base = self.page_base(idx);
        let mut header = [0u8; HEADER_LEN];
        self.flash
            .read(base, &mut header)
            .map_err(FlashError::Flash)?;

        if header[0..4] != MAGIC {
            // A never-written page (erase leaves every byte `0xFF`) is the
            // expected steady state on a fresh device — not worth logging.
            // Anything else here (a foreign format, a page that predates
            // this backend) is genuinely unexpected, so it's surfaced rather
            // than silently treated the same as "blank".
            if header != [0xFFu8; HEADER_LEN] {
                tracing::debug!(
                    page = idx,
                    "flash page header magic mismatch; treating as empty"
                );
            }
            return Ok(None);
        }
        let generation = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let want_crc = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if len > self.capacity() {
            tracing::warn!(
                page = idx,
                len,
                capacity = self.capacity(),
                "flash page header claims an out-of-bounds length; discarding"
            );
            return Ok(None);
        }

        // Stream the payload through CRC in bounded chunks — never buffer the
        // whole blob — so validation stays allocation-free for any size.
        let mut crc = Crc32::new();
        let mut remaining = len;
        let mut offset = base + HEADER_LEN as u32;
        let mut chunk = [0u8; CRC_CHUNK];
        while remaining > 0 {
            let n = remaining.min(CRC_CHUNK);
            self.flash
                .read(offset, &mut chunk[..n])
                .map_err(FlashError::Flash)?;
            crc.update(&chunk[..n]);
            remaining -= n;
            offset += n as u32;
        }
        if crc.finalize() != want_crc {
            tracing::warn!(
                page = idx,
                generation,
                "flash page failed CRC validation; discarding as a torn write"
            );
            return Ok(None);
        }
        Ok(Some(PageHeader { generation, len }))
    }

    /// The higher-generation valid page and its header, or `None` if neither
    /// page holds a valid blob (a fresh store, or both torn/corrupt). Ties
    /// can't legitimately occur (each `save` strictly increments the
    /// generation it writes), so an equal-generation pair — which shouldn't
    /// arise in practice — resolves to page 0 arbitrarily.
    fn newest_valid(&mut self) -> Result<Option<(u32, PageHeader)>, FlashError<F::Error>> {
        let h0 = self.read_valid_header(0)?;
        let h1 = self.read_valid_header(1)?;
        Ok(match (h0, h1) {
            (None, None) => None,
            (Some(h), None) => Some((0, h)),
            (None, Some(h)) => Some((1, h)),
            (Some(a), Some(b)) if b.generation > a.generation => Some((1, b)),
            (Some(a), _) => Some((0, a)),
        })
    }
}

impl<F: NorFlash> DurableStore for FlashStore<F> {
    type Error = FlashError<F::Error>;

    fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some((idx, header)) = self.newest_valid()? else {
            return Ok(None);
        };

        if header.len > out.len() {
            return Err(FlashError::BufferTooSmall {
                len: header.len,
                buf: out.len(),
            });
        }
        let payload_at = self.page_base(idx) + HEADER_LEN as u32;
        self.flash
            .read(payload_at, &mut out[..header.len])
            .map_err(FlashError::Flash)?;
        Ok(Some(header.len))
    }

    fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let capacity = self.capacity();
        if data.len() > capacity {
            return Err(FlashError::BlobTooLarge {
                len: data.len(),
                capacity,
            });
        }

        // Target the page that is *not* the newest valid one, so a crash
        // mid-write can only damage the older copy; the newest good blob
        // survives. With neither page valid, page 0 is a fine first home.
        let (target, next_gen) = match self.newest_valid()? {
            None => (0, 0),
            Some((idx, header)) => (idx ^ 1, header.generation.wrapping_add(1)),
        };

        let mut crc = Crc32::new();
        crc.update(data);
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..8].copy_from_slice(&next_gen.to_le_bytes());
        header[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&crc.finalize().to_le_bytes());

        let base = self.page_base(target);
        self.flash
            .erase(base, base + F::ERASE_SIZE as u32)
            .map_err(FlashError::Flash)?;

        // Every write must be `WRITE_SIZE`-aligned in both offset and length.
        // The header is `HEADER_LEN` (a multiple of every supported word) at
        // the page base (erase-aligned); the payload's whole-word prefix
        // writes straight from `data`, and its sub-word tail is padded with
        // erased `0xFF` in a small stack scratch.
        let w = F::WRITE_SIZE;
        // Fixed at monomorphization, so this costs one check per `F` rather
        // than a release-mode-dead `debug_assert!` on every call.
        const {
            assert!(
                F::WRITE_SIZE <= MAX_WRITE_SIZE && HEADER_LEN.is_multiple_of(F::WRITE_SIZE),
                "unsupported flash WRITE_SIZE"
            );
        }
        self.flash.write(base, &header).map_err(FlashError::Flash)?;

        let payload_base = base + HEADER_LEN as u32;
        let aligned = data.len() - (data.len() % w);
        if aligned > 0 {
            self.flash
                .write(payload_base, &data[..aligned])
                .map_err(FlashError::Flash)?;
        }
        let rem = data.len() - aligned;
        if rem > 0 {
            let mut tail = [0xFFu8; MAX_WRITE_SIZE];
            tail[..rem].copy_from_slice(&data[aligned..]);
            self.flash
                .write(payload_base + aligned as u32, &tail[..w])
                .map_err(FlashError::Flash)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_storage::nor_flash::ErrorType;
    use embedded_storage::nor_flash::NorFlashError;
    use embedded_storage::nor_flash::NorFlashErrorKind;
    use embedded_storage::nor_flash::ReadNorFlash;

    const TEST_PAGE: usize = 128;
    const TEST_PAGES: usize = 2;

    /// Error type for the in-memory flash double.
    #[derive(Debug, PartialEq, Eq)]
    enum MemErr {
        OutOfBounds,
        NotAligned,
    }

    impl NorFlashError for MemErr {
        fn kind(&self) -> NorFlashErrorKind {
            match self {
                MemErr::OutOfBounds => NorFlashErrorKind::OutOfBounds,
                MemErr::NotAligned => NorFlashErrorKind::NotAligned,
            }
        }
    }

    /// An in-memory [`NorFlash`] modelling real NOR semantics: erase sets a
    /// page to `0xFF`, and a write can only *clear* bits (`&=`), never set
    /// them — so a misuse that rewrites a word without erasing first would
    /// corrupt exactly as hardware would. `WRITE_SIZE` is 4, matching the
    /// nRF52 NVMC.
    struct MemFlash {
        mem: Vec<u8>,
    }

    impl MemFlash {
        fn new() -> Self {
            Self {
                mem: vec![0xFF; TEST_PAGE * TEST_PAGES],
            }
        }
    }

    impl ErrorType for MemFlash {
        type Error = MemErr;
    }

    impl ReadNorFlash for MemFlash {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let start = offset as usize;
            let end = start + bytes.len();
            if end > self.mem.len() {
                return Err(MemErr::OutOfBounds);
            }
            bytes.copy_from_slice(&self.mem[start..end]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.mem.len()
        }
    }

    impl NorFlash for MemFlash {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = TEST_PAGE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            if !(from as usize).is_multiple_of(TEST_PAGE)
                || !(to as usize).is_multiple_of(TEST_PAGE)
            {
                return Err(MemErr::NotAligned);
            }
            if to as usize > self.mem.len() || from > to {
                return Err(MemErr::OutOfBounds);
            }
            for b in &mut self.mem[from as usize..to as usize] {
                *b = 0xFF;
            }
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            if !(offset as usize).is_multiple_of(Self::WRITE_SIZE)
                || !bytes.len().is_multiple_of(Self::WRITE_SIZE)
            {
                return Err(MemErr::NotAligned);
            }
            let start = offset as usize;
            let end = start + bytes.len();
            if end > self.mem.len() {
                return Err(MemErr::OutOfBounds);
            }
            // NOR: writing only clears bits; erased 0xFF cells take the data
            // verbatim, and any accidental double-write would AND, not assign.
            for (dst, &src) in self.mem[start..end].iter_mut().zip(bytes) {
                *dst &= src;
            }
            Ok(())
        }
    }

    /// A [`MemFlash`] wrapper that fails the `n`th `write`/`erase` call it
    /// sees (0-indexed across both, in the order `NorFlash` methods are
    /// actually invoked), and passes every other call straight through. Lets
    /// a test inject a real driver failure into `FlashStore::save`'s own
    /// error-propagation path, rather than only simulating a torn write by
    /// poking bytes after a successful save.
    struct FlakyFlash {
        inner: MemFlash,
        fail_write_at: Option<usize>,
        fail_erase_at: Option<usize>,
        write_count: usize,
        erase_count: usize,
    }

    impl FlakyFlash {
        fn new(inner: MemFlash) -> Self {
            Self {
                inner,
                fail_write_at: None,
                fail_erase_at: None,
                write_count: 0,
                erase_count: 0,
            }
        }
    }

    impl ErrorType for FlakyFlash {
        type Error = MemErr;
    }

    impl ReadNorFlash for FlakyFlash {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.inner.read(offset, bytes)
        }

        fn capacity(&self) -> usize {
            self.inner.capacity()
        }
    }

    impl NorFlash for FlakyFlash {
        const WRITE_SIZE: usize = MemFlash::WRITE_SIZE;
        const ERASE_SIZE: usize = MemFlash::ERASE_SIZE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            let idx = self.erase_count;
            self.erase_count += 1;
            if self.fail_erase_at == Some(idx) {
                return Err(MemErr::OutOfBounds);
            }
            self.inner.erase(from, to)
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            let idx = self.write_count;
            self.write_count += 1;
            if self.fail_write_at == Some(idx) {
                return Err(MemErr::OutOfBounds);
            }
            self.inner.write(offset, bytes)
        }
    }

    /// A fresh store (nothing ever written) loads as empty, not an error.
    #[test]
    fn load_before_any_save_is_none() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(store.load(&mut buf).unwrap(), None);
    }

    /// A saved blob round-trips through load byte-for-byte, including a
    /// sub-word-length payload (exercising the tail-padding write path).
    #[test]
    fn save_then_load_round_trips() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        let data = b"the quick brown fox"; // 19 bytes: not a multiple of 4
        store.save(data).unwrap();

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], data);
    }

    /// A second save replaces the first, and lands on the *other* page
    /// (ping-pong) so a torn write can't clobber the last good copy.
    #[test]
    fn second_save_replaces_first_on_the_other_page() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        store.save(b"version one").unwrap();
        store.save(b"v2").unwrap();

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"v2");

        // The first save went to page 0, the second to page 1: both page
        // headers should carry the magic, confirming the alternation.
        assert_eq!(store.flash.mem[0..4], MAGIC);
        assert_eq!(store.flash.mem[TEST_PAGE..TEST_PAGE + 4], MAGIC);
    }

    /// Many saves keep alternating pages and always reload the newest blob —
    /// the generation counter, not the page, decides the winner.
    #[test]
    fn repeated_saves_always_reload_newest() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        for i in 0u8..10 {
            let blob = [i; 5];
            store.save(&blob).unwrap();
            let mut buf = [0u8; 64];
            let n = store.load(&mut buf).unwrap().unwrap();
            assert_eq!(&buf[..n], &blob, "iteration {i}");
        }
    }

    /// A write torn by power loss (valid-looking header, payload that fails
    /// CRC) is discarded on load, which falls back to the previous intact
    /// page — the core atomicity guarantee of this backend.
    #[test]
    fn torn_write_falls_back_to_previous_generation() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        store.save(b"good-gen0").unwrap(); // page 0, generation 0
        store.save(b"good-gen1").unwrap(); // page 1, generation 1

        // Simulate a torn save targeting page 0 (the older page the next real
        // save would pick): erase it, write a header claiming a newer
        // generation, but leave a payload that doesn't match its CRC.
        store.flash.erase(0, TEST_PAGE as u32).unwrap();
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..8].copy_from_slice(&99u32.to_le_bytes()); // highest generation
        header[8..12].copy_from_slice(&8u32.to_le_bytes()); // claims 8-byte payload
        header[12..16].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // wrong CRC
        store.flash.write(0, &header).unwrap();
        store.flash.write(HEADER_LEN as u32, b"corrupt!").unwrap();

        // Despite page 0's higher generation, its CRC fails, so load returns
        // page 1's intact generation-1 blob.
        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"good-gen1");
    }

    /// A blob larger than a page's capacity is rejected on save, not spilled.
    #[test]
    fn save_rejects_oversized_blob() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        let capacity = store.capacity();
        let too_big = vec![0u8; capacity + 1];
        assert_eq!(
            store.save(&too_big),
            Err(FlashError::BlobTooLarge {
                len: capacity + 1,
                capacity,
            })
        );
    }

    /// A stored blob larger than the caller's read buffer is an error, not a
    /// silent truncation.
    #[test]
    fn load_rejects_undersized_buffer() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        store.save(b"twenty-byte payload!").unwrap(); // 20 bytes

        let mut tiny = [0u8; 4];
        assert_eq!(
            store.load(&mut tiny),
            Err(FlashError::BufferTooSmall { len: 20, buf: 4 })
        );
    }

    /// An empty blob is a legitimate value: it saves and reloads as length 0,
    /// distinct from a never-written store's `None`.
    #[test]
    fn empty_blob_round_trips_as_zero_length() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        store.save(b"").unwrap();

        let mut buf = [0u8; 64];
        assert_eq!(store.load(&mut buf).unwrap(), Some(0));
    }

    /// A payload whose length is an exact multiple of `WRITE_SIZE` isolates
    /// the "no tail padding needed" branch (`rem == 0`) — every other test's
    /// payload deliberately isn't a multiple of 4, so this closes that gap.
    #[test]
    fn save_then_load_round_trips_a_write_size_aligned_payload() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        let data = [0xABu8; 20]; // 20 % WRITE_SIZE(4) == 0
        store.save(&data).unwrap();

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], &data[..]);
    }

    /// A payload at exactly `capacity()` bytes — the largest a page can ever
    /// hold — round-trips; only `capacity() + 1` was previously tested (for
    /// rejection), leaving the boundary itself unexercised.
    #[test]
    fn save_then_load_round_trips_at_exact_capacity() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        let capacity = store.capacity();
        let data = vec![0x5Au8; capacity];
        store.save(&data).unwrap();

        let mut buf = vec![0u8; capacity];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], &data[..]);
    }

    /// `new` rejects a `base_offset` that isn't erase-aligned, rather than
    /// building a store whose `page_base` arithmetic silently addresses the
    /// wrong location.
    #[test]
    fn new_rejects_misaligned_base_offset() {
        assert!(matches!(
            FlashStore::new(MemFlash::new(), 1),
            Err(FlashError::Unaligned { .. })
        ));
    }

    /// `new` rejects a placement whose two pages don't fit inside the flash
    /// device's own reported capacity.
    #[test]
    fn new_rejects_out_of_bounds_placement() {
        // MemFlash::new() has exactly TEST_PAGES(2) pages; basing the store
        // one page in would need a 3rd page that doesn't exist.
        assert!(matches!(
            FlashStore::new(MemFlash::new(), TEST_PAGE as u32),
            Err(FlashError::OutOfBounds { .. })
        ));
    }

    /// A store placed at a nonzero `base_offset` — the production shape (the
    /// nRF52840 binary reserves the *top* two pages of flash, not the
    /// bottom, so `base_offset` is never 0 on real hardware) — round-trips
    /// correctly, and never writes outside its own two reserved pages.
    #[test]
    fn save_and_load_round_trip_at_a_nonzero_base_offset() {
        let mut flash = MemFlash::new();
        flash.mem.resize(TEST_PAGE * 4, 0xFF); // grow to 4 pages
        let base = (TEST_PAGE * 2) as u32; // store lives in the top two
        let mut store = FlashStore::new(flash, base).unwrap();

        store.save(b"hello at offset").unwrap();
        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello at offset");

        assert_eq!(
            &store.flash.mem[0..TEST_PAGE * 2],
            &vec![0xFFu8; TEST_PAGE * 2][..],
            "a store based at page 2 must never touch pages 0-1"
        );
    }

    /// A real flash driver failure during `save` (not a post-hoc torn-byte
    /// simulation) propagates as `Err(FlashError::Flash(_))`, and — because
    /// `save` always targets the page that ISN'T the newest valid one — the
    /// previously-good page is untouched and still loads correctly.
    #[test]
    fn save_propagates_a_write_failure_without_corrupting_the_prior_generation() {
        let mut store = FlashStore::new(FlakyFlash::new(MemFlash::new()), 0).unwrap();
        store.save(b"good-gen0").unwrap(); // succeeds: page 0, generation 0

        // Fail the very next write() call — the header write of the second
        // save, which targets page 1.
        store.flash.fail_write_at = Some(store.flash.write_count);

        let result = store.save(b"this-save-fails");
        assert!(matches!(result, Err(FlashError::Flash(_))));

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(
            &buf[..n],
            b"good-gen0",
            "the untouched prior-generation page must still load correctly"
        );
    }

    /// Same guarantee as above, but the injected failure is in `erase`
    /// (which `save` calls before either `write`) rather than `write`.
    #[test]
    fn save_propagates_an_erase_failure_without_corrupting_the_prior_generation() {
        let mut store = FlashStore::new(FlakyFlash::new(MemFlash::new()), 0).unwrap();
        store.save(b"good-gen0").unwrap();

        store.flash.fail_erase_at = Some(store.flash.erase_count);

        let result = store.save(b"this-save-fails");
        assert!(matches!(result, Err(FlashError::Flash(_))));

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"good-gen0");
    }

    /// Both pages corrupt simultaneously (e.g. two independent power-loss
    /// events over the device's lifetime, one per page) reads as `None` —
    /// same as a never-written store — rather than returning stale or torn
    /// data. This is the scenario `load_or_init_identity` treats identically
    /// to "never provisioned" (see that module's doc comment on the
    /// tradeoff this implies for a caller built on top of this store).
    #[test]
    fn both_pages_corrupt_reads_as_empty_not_stale_data() {
        let mut store = FlashStore::new(MemFlash::new(), 0).unwrap();
        store.save(b"gen0").unwrap();
        store.save(b"gen1").unwrap();

        // Directly corrupt one CRC byte in each page's header. This models
        // arbitrary bit corruption (not a legitimate flash operation, so it
        // bypasses NorFlash::write's AND-only semantics) — the same
        // observable effect as two independent torn writes over time.
        for page_base in [0usize, TEST_PAGE] {
            store.flash.mem[page_base + 12] ^= 0xFF;
        }

        let mut buf = [0u8; 64];
        assert_eq!(
            store.load(&mut buf).unwrap(),
            None,
            "both pages corrupt must read as empty, never stale/torn data"
        );
    }
}
