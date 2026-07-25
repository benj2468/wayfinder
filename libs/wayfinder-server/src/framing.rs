//! Length-delimited framing for the embedded management transport.
//!
//! The `std` server frames management messages with `tokio_util`'s
//! [`LengthDelimitedCodec`] in its default configuration: a **4-byte
//! big-endian** length prefix giving the body length (the prefix itself is not
//! counted), followed by that many payload bytes. This module reproduces that
//! exact wire shape over an [`embedded_io_async`] byte stream so an embedded
//! node speaks the same framing to the same [`wayfinder-client`], with no tokio
//! and no heap beyond the single body buffer.
//!
//! [`LengthDelimitedCodec`]: https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html
//! [`wayfinder-client`]: https://docs.rs/wayfinder-client

use alloc::vec::Vec;

use embedded_io_async::{Read, ReadExactError, Write};

/// The largest frame body this transport will read.
///
/// A remote peer supplies the 4-byte length prefix, so an unbounded value would
/// let it demand an arbitrarily large allocation on a memory-constrained node.
/// 4 KiB comfortably covers a routing-table response on the node counts an
/// embedded relay actually sees (dozens of originators, a couple of paths each
/// — a few hundred entries at ~20-50 encoded bytes apiece) while staying tiny
/// relative to `tokio_util`'s 8 MiB default. A caller sizing an embedded node's
/// heap around this cap should budget for **two** buffers at this size (`serve`
/// keeps one in each direction) plus the response `Vec`s a query itself builds
/// — see `HEAP_SIZE_BYTES` in `bins/wayfinder-nrf52840`. A declared length above
/// this is a protocol error, not something the node tries to allocate for.
pub const MAX_FRAME_LEN: usize = 4 * 1024;

/// Why reading or writing a length-delimited frame failed.
///
/// `E` is the underlying stream's error type (`Read::Error` / `Write::Error`).
#[derive(Debug)]
pub enum FrameError<E> {
    /// The underlying byte stream returned an I/O error.
    Io(E),
    /// The stream ended part-way through a frame — a clean peer disconnect
    /// mid-frame, or before the next frame's length prefix. The caller stops
    /// serving the connection rather than treating it as corruption.
    UnexpectedEof,
    /// A length exceeded [`MAX_FRAME_LEN`] — either a peer's 4-byte length
    /// prefix on read (the stream can no longer be trusted to be framed
    /// correctly, so the caller closes it instead of trying to allocate or
    /// resynchronise), or a body handed to [`write_frame`] on write (refused
    /// locally, before anything is sent, since a peer bounded by the same cap
    /// would reject it anyway).
    Oversized(u32),
}

/// Collapse a [`ReadExactError`] into a [`FrameError`]: a short read becomes
/// [`FrameError::UnexpectedEof`], any other stream error is wrapped as
/// [`FrameError::Io`].
fn from_read_exact<E>(err: ReadExactError<E>) -> FrameError<E> {
    match err {
        ReadExactError::UnexpectedEof => FrameError::UnexpectedEof,
        ReadExactError::Other(e) => FrameError::Io(e),
    }
}

/// Read one length-delimited frame from `reader` into `buf`.
///
/// Reads the 4-byte big-endian length prefix, then exactly that many body
/// bytes. `buf` is cleared and refilled with just the body (the prefix is
/// consumed but not stored), so a caller can reuse one buffer across frames
/// rather than allocating per request. A declared length above [`MAX_FRAME_LEN`]
/// is rejected as [`FrameError::Oversized`] before any body is read.
pub async fn read_frame<R: Read>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<(), FrameError<R::Error>> {
    let mut len_prefix = [0u8; 4];
    reader
        .read_exact(&mut len_prefix)
        .await
        .map_err(from_read_exact)?;
    let len = u32::from_be_bytes(len_prefix);
    if len as usize > MAX_FRAME_LEN {
        return Err(FrameError::Oversized(len));
    }
    buf.clear();
    buf.resize(len as usize, 0);
    reader.read_exact(buf).await.map_err(from_read_exact)?;
    Ok(())
}

/// Write `body` to `writer` as one length-delimited frame: the 4-byte
/// big-endian length prefix followed by the body, then flush.
///
/// A body longer than [`MAX_FRAME_LEN`] is refused with
/// [`FrameError::Oversized`] rather than emitted — a peer bounded by the same
/// cap on read would reject it anyway, so this fails locally where the offending
/// message is still identifiable.
pub async fn write_frame<W: Write>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), FrameError<W::Error>> {
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::Oversized(body.len() as u32));
    }
    let len_prefix = (body.len() as u32).to_be_bytes();
    writer
        .write_all(&len_prefix)
        .await
        .map_err(FrameError::Io)?;
    writer.write_all(body).await.map_err(FrameError::Io)?;
    writer.flush().await.map_err(FrameError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use core::convert::Infallible;

    use super::*;

    /// An in-memory [`Read`] over a fixed byte slice that returns at most
    /// `chunk` bytes per call, so `read_exact`'s internal loop across the length
    /// prefix and body is actually exercised (a single-shot reader would hide a
    /// partial-read bug).
    struct ChunkReader<'a> {
        data: &'a [u8],
        pos: usize,
        chunk: usize,
    }

    impl embedded_io_async::ErrorType for ChunkReader<'_> {
        type Error = Infallible;
    }

    impl Read for ChunkReader<'_> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len()).min(self.chunk);
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    /// An in-memory [`Write`] that accumulates everything written, for asserting
    /// the exact bytes a frame produces.
    #[derive(Default)]
    struct VecWriter {
        written: Vec<u8>,
        flushes: usize,
    }

    impl embedded_io_async::ErrorType for VecWriter {
        type Error = Infallible;
    }

    impl Write for VecWriter {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        futures::executor::block_on(fut)
    }

    #[test]
    fn write_frame_emits_be_length_prefix_then_body() {
        let mut writer = VecWriter::default();
        block_on(write_frame(&mut writer, &[0xaa, 0xbb, 0xcc])).unwrap();
        // 3-byte body => prefix 00 00 00 03, then the body.
        assert_eq!(writer.written, vec![0, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
        assert_eq!(writer.flushes, 1, "the frame is flushed exactly once");
    }

    #[test]
    fn read_frame_recovers_body_across_partial_reads() {
        // A well-formed frame delivered a byte at a time: read_exact must
        // reassemble both the 4-byte prefix and the body from single-byte reads.
        let wire = [0, 0, 0, 4, 1, 2, 3, 4];
        let mut reader = ChunkReader {
            data: &wire,
            pos: 0,
            chunk: 1,
        };
        let mut buf = Vec::new();
        block_on(read_frame(&mut reader, &mut buf)).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_write_then_read_is_identity() {
        let body = [9u8, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        let mut writer = VecWriter::default();
        block_on(write_frame(&mut writer, &body)).unwrap();

        let mut reader = ChunkReader {
            data: &writer.written,
            pos: 0,
            chunk: 3,
        };
        let mut buf = Vec::new();
        block_on(read_frame(&mut reader, &mut buf)).unwrap();
        assert_eq!(buf, body);
    }

    #[test]
    fn read_frame_reuses_and_clears_the_buffer() {
        // A buffer left over from a longer previous frame must not leak stale
        // bytes into a shorter one.
        let mut buf = vec![0xff; 100];
        let wire = [0, 0, 0, 2, 42, 43];
        let mut reader = ChunkReader {
            data: &wire,
            pos: 0,
            chunk: 8,
        };
        block_on(read_frame(&mut reader, &mut buf)).unwrap();
        assert_eq!(buf, vec![42, 43]);
    }

    #[test]
    fn read_frame_rejects_an_oversized_length_prefix() {
        // A prefix declaring MAX_FRAME_LEN + 1 is refused before any body read.
        let len = (MAX_FRAME_LEN as u32) + 1;
        let wire = len.to_be_bytes();
        let mut reader = ChunkReader {
            data: &wire,
            pos: 0,
            chunk: 4,
        };
        let mut buf = Vec::new();
        let err = block_on(read_frame(&mut reader, &mut buf)).unwrap_err();
        assert!(matches!(err, FrameError::Oversized(l) if l == len));
    }

    #[test]
    fn read_frame_reports_unexpected_eof_on_a_truncated_body() {
        // Prefix promises 4 body bytes but only 2 follow.
        let wire = [0, 0, 0, 4, 1, 2];
        let mut reader = ChunkReader {
            data: &wire,
            pos: 0,
            chunk: 8,
        };
        let mut buf = Vec::new();
        let err = block_on(read_frame(&mut reader, &mut buf)).unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }

    #[test]
    fn read_frame_reports_unexpected_eof_on_a_closed_stream() {
        // No bytes at all: a clean disconnect between frames.
        let wire: [u8; 0] = [];
        let mut reader = ChunkReader {
            data: &wire,
            pos: 0,
            chunk: 8,
        };
        let mut buf = Vec::new();
        let err = block_on(read_frame(&mut reader, &mut buf)).unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }

    #[test]
    fn write_frame_refuses_a_body_over_the_cap() {
        let mut writer = VecWriter::default();
        let body = vec![0u8; MAX_FRAME_LEN + 1];
        let err = block_on(write_frame(&mut writer, &body)).unwrap_err();
        assert!(matches!(err, FrameError::Oversized(_)));
        assert!(writer.written.is_empty(), "nothing is written on refusal");
    }
}
