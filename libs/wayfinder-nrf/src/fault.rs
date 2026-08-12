//! Panic and HardFault handling: report, then reboot — and stop rebooting once
//! the fault has proven it recurs every boot.
//!
//! See this crate's `CLAUDE.md` for why rebooting is the right default and
//! halting after [`MAX_CONSECUTIVE_FAULTS`] the right backstop. Both handlers
//! share one budget in [`FAULT_GUARD`], and both leave behind what killed the
//! board: a HardFault its diagnostic registers ([`FAULT_RECORD`]), a panic its
//! rendered text ([`PANIC_MSG`]). [`report_retained`] logs either on the next
//! boot.
//!
//! Retaining the panic text is what makes a probe-less board debuggable at all.
//! The handler's `rprintln!` reaches an RTT channel that only an attached debug
//! probe can read, and a dongle has no probe — so before this, a panic reset the
//! node leaving *no* evidence anywhere, indistinguishable from a power glitch or
//! a host-side USB teardown.
//!
//! Every static here lives in `.uninit`, which is the mechanism rather than a
//! detail: `cortex-m-rt` re-initialises `.bss`/`.data` on the very reset whose
//! cause they carry, so a counter kept anywhere else would never exceed 1.
//! `.uninit` escapes that zeroing and nRF52 RAM survives `SYSRESETREQ`, at the
//! cost of holding garbage after a power-on — hence the magic words. Each is an
//! atomic or an array of one atomic type, never a struct, which LLVM splits into
//! per-field globals that land back in `.bss`; and all of them are only as
//! trustworthy as `flip-link` keeping the descending stack out of `.uninit`.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::compiler_fence;

use tracing::error;

/// Consecutive faults tolerated before the handlers halt instead of rebooting.
/// Three is enough for a transient fault to clear and few enough that a
/// deterministic one settles quickly.
pub const MAX_CONSECUTIVE_FAULTS: u32 = 3;

/// Roughly how long a handler holds the CPU before resetting, so an attached
/// probe can drain the message out of the RTT buffer (which does not survive the
/// reset). Cycles rather than a `Timer`: the executor is gone by now.
///
/// 200 ms at 64 MHz, comfortably above `probe-rs`'s RTT poll interval and no
/// more. It was two seconds back when RTT was the only record a panic left;
/// now that both handlers retain their evidence across the reset, this delay
/// only buys an attached probe the untruncated text, and everything it costs is
/// paid by boards that have no probe to drain. On a USB-powered node that cost
/// is real: the CPU is not servicing USBD for the whole delay, which is time the
/// host spends deciding the device has fallen off the bus.
const DRAIN_CYCLES: u32 = 64_000_000 / 5;

/// Consecutive-fault count, high 24 bits [`GUARD_MAGIC`], low 8 the count.
#[unsafe(link_section = ".uninit.FAULT_GUARD")]
static FAULT_GUARD: AtomicU32 = AtomicU32::new(0);

/// Marks [`FAULT_GUARD`] as ours rather than post-power-on garbage (`b"WAF"`).
const GUARD_MAGIC: u32 = 0x5741_4600;

/// Selects the magic half of [`FAULT_GUARD`].
const GUARD_MAGIC_MASK: u32 = 0xFFFF_FF00;

/// Selects the count half of [`FAULT_GUARD`], and is also where the count
/// saturates — it only has to distinguish "below [`MAX_CONSECUTIVE_FAULTS`]"
/// from "at or above".
const GUARD_COUNT_MASK: u32 = 0x0000_00FF;

/// Declare this boot healthy, resetting the consecutive-fault count.
///
/// Call once a fault from here on would be a runtime problem worth rebooting
/// out of rather than a bring-up failure that recurs identically. Everything
/// deterministic — `sd_ble_enable` sizing, identity load, USB — happens first,
/// so those still latch the counter and eventually halt.
pub fn mark_boot_healthy() {
    FAULT_GUARD.store(GUARD_MAGIC, Relaxed);
}

/// Record one more fault and return the resulting consecutive count (1 for the
/// first since the last healthy boot, or since power-on).
fn bump_fault_count() -> u32 {
    let stored = FAULT_GUARD.load(Relaxed);
    let count = if stored & GUARD_MAGIC_MASK == GUARD_MAGIC {
        ((stored & GUARD_COUNT_MASK) + 1).min(GUARD_COUNT_MASK)
    } else {
        1
    };
    FAULT_GUARD.store(GUARD_MAGIC | count, Relaxed);
    count
}

/// Halt forever, for a fault that has proven it recurs every boot.
fn halt() -> ! {
    loop {
        compiler_fence(Ordering::SeqCst);
    }
}

/// Reset the chip, after a pause long enough for a probe to drain RTT.
fn reset() -> ! {
    cortex_m::asm::delay(DRAIN_CYCLES);
    cortex_m::peripheral::SCB::sys_reset()
}

/// Longest retained panic text, in bytes.
///
/// Sized against what can actually be read back rather than against the message
/// a panic might produce: the record surfaces as one `error!`, and the log ring
/// caps a record's rendered message *and* its fields at
/// [`wayfinder_log::MESSAGE_CAP`] (160). The event's own text plus the
/// `detail="…"` wrapper accounts for 40 of those, so bytes past 120 could never
/// be read out. `Debug` escaping of a quote or backslash in the message clips a
/// little more.
const PANIC_MSG_LEN: usize = 120;

/// Marks [`PANIC_HEADER`] as written by [`panic`] rather than being
/// post-power-on garbage (`b"WAP"`), in the high 24 bits.
const PANIC_MAGIC: u32 = 0x5741_5000;

/// Selects the magic half of [`PANIC_HEADER`].
const PANIC_MAGIC_MASK: u32 = 0xFFFF_FF00;

/// Selects the length half of [`PANIC_HEADER`] — the byte count written to
/// [`PANIC_MSG`], which [`PANIC_MSG_LEN`] keeps well inside a single byte.
const PANIC_LEN_MASK: u32 = 0x0000_00FF;

/// [`PANIC_MAGIC`] plus the retained message length. Written *after*
/// [`PANIC_MSG`], so a reset landing mid-write leaves no record rather than
/// half of one.
#[unsafe(link_section = ".uninit.PANIC_HEADER")]
static PANIC_HEADER: AtomicU32 = AtomicU32::new(0);

/// A panic's rendered location and message, retained across the reset that
/// follows so the next boot can report what killed the previous one. Valid only
/// when [`PANIC_HEADER`] carries [`PANIC_MAGIC`], and only for the length it
/// carries.
///
/// `[AtomicU8; N]` for the same reason [`FAULT_RECORD`] is `[AtomicU32; N]`: an
/// array of one scalar type stays a single global that keeps its
/// `#[link_section]`.
#[unsafe(link_section = ".uninit.PANIC_MSG")]
static PANIC_MSG: [AtomicU8; PANIC_MSG_LEN] = [const { AtomicU8::new(0) }; PANIC_MSG_LEN];

/// A [`core::fmt::Write`] sink landing formatted text straight in [`PANIC_MSG`].
///
/// Straight into the static rather than via a stack buffer, because the handler
/// runs on whatever stack the panicking task had left. Overflow truncates
/// silently instead of erroring: a failed `write_str` aborts the whole format
/// run, which would cost the location prefix too — the most useful part.
struct PanicSink {
    /// Bytes written so far, and the index of the next slot.
    len: usize,
}

impl core::fmt::Write for PanicSink {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &byte in s.as_bytes() {
            let Some(slot) = PANIC_MSG.get(self.len) else {
                return Ok(());
            };
            // `PanicInfo` puts a newline between the location and the message,
            // and the ring stores one record as one line.
            slot.store(if byte < 0x20 { b' ' } else { byte }, Relaxed);
            self.len += 1;
        }
        Ok(())
    }
}

/// Capture `info` into [`PANIC_MSG`] for the next boot to report.
fn record_panic(info: &core::panic::PanicInfo) {
    // Invalidate first, so the record is never readable in a partial state.
    PANIC_HEADER.store(0, Relaxed);

    let mut sink = PanicSink { len: 0 };
    // `PanicInfo`'s own `Display` is location *and* message — the same text the
    // RTT line below prints. Discarding the result is safe: the sink truncates
    // rather than failing.
    let _ = core::fmt::write(&mut sink, format_args!("{info}"));

    PANIC_HEADER.store(PANIC_MAGIC | sink.len as u32, Relaxed);
}

/// Records the panic for the next boot and prints it over RTT, then reboots —
/// or halts, once [`MAX_CONSECUTIVE_FAULTS`] reboots in a row have failed to
/// clear the fault.
///
/// Writes to the print channel `wayfinder_log::init()` already set up, rather
/// than opening a second RTT channel — hence the `rtt-target` version pin in
/// `Cargo.toml`. That channel needs an attached probe to be read at all, which
/// is why the retained record exists: it is the only path on a board without
/// one, and it works for a panic that happened before `init()` too.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let count = bump_fault_count();
    record_panic(info);

    // `rprintln!` runs its format string through `concat!`, so implicitly
    // captured identifiers are not available — every value is positional.
    rtt_target::rprintln!("panic ({}/{}): {}", count, MAX_CONSECUTIVE_FAULTS, info);

    if count >= MAX_CONSECUTIVE_FAULTS {
        rtt_target::rprintln!("panic: {} consecutive; halting", MAX_CONSECUTIVE_FAULTS);
        halt();
    }
    rtt_target::rprintln!("panic: resetting");
    reset()
}

/// `SCB_CFSR`, the Configurable Fault Status Register: `MMFSR`/`BFSR`/`UFSR`
/// packed into one word, saying *why* a fault escalated.
const SCB_CFSR: *const u32 = 0xE000_ED28 as *const u32;

/// `SCB_HFSR`, the HardFault Status Register. Bit 30 (`FORCED`) means a
/// configurable fault escalated, which is the usual case here.
const SCB_HFSR: *const u32 = 0xE000_ED2C as *const u32;

/// `SCB_MMFAR`, the faulting data address for a memory management fault. Valid
/// only when `CFSR`'s `MMARVALID` (bit 7) is set.
const SCB_MMFAR: *const u32 = 0xE000_ED34 as *const u32;

/// `SCB_BFAR`, the faulting data address for a bus fault. Valid only when
/// `CFSR`'s `BFARVALID` (bit 15) is set.
const SCB_BFAR: *const u32 = 0xE000_ED38 as *const u32;

/// Word count of [`FAULT_RECORD`] — one slot per `IDX_*` constant below, plus
/// the magic word.
const FAULT_RECORD_WORDS: usize = 7;

/// [`FAULT_RECORD`] slot indices. The single source of truth for the layout:
/// the write side ([`HardFault`]) and read side ([`report_retained`]) both
/// index through these names rather than each hand-matching bare integers, so
/// a slot can't drift out of correspondence between the two.
const IDX_MAGIC: usize = 0;
const IDX_PC: usize = 1;
const IDX_LR: usize = 2;
const IDX_CFSR: usize = 3;
const IDX_HFSR: usize = 4;
const IDX_MMFAR: usize = 5;
const IDX_BFAR: usize = 6;

/// Marks [`FAULT_RECORD`] as written by [`HardFault`] rather than being
/// post-power-on garbage (`b"WAFF"`).
const RECORD_MAGIC: u32 = 0x5741_4646;

/// A HardFault's diagnostic registers, retained across the reset that follows so
/// the next boot can report what killed the previous one.
#[unsafe(link_section = ".uninit.FAULT_RECORD")]
static FAULT_RECORD: [AtomicU32; FAULT_RECORD_WORDS] =
    [const { AtomicU32::new(0) }; FAULT_RECORD_WORDS];

/// A one-line guess at what a `CFSR`/`HFSR` pair means, to save decoding bits by
/// hand at the point the log is read.
///
/// Ordered by specificity, not bit position: the stacking errors come first as
/// the signature of a stack overflow, whose fix is unlike the others'.
/// `IMPRECISERR` is called out as the case where the recorded PC is not the
/// culprit.
fn cause(cfsr: u32, hfsr: u32) -> &'static str {
    const MMFSR_IACCVIOL: u32 = 1 << 0;
    const MMFSR_DACCVIOL: u32 = 1 << 1;
    const MMFSR_MSTKERR: u32 = 1 << 4;
    const BFSR_IBUSERR: u32 = 1 << 8;
    const BFSR_PRECISERR: u32 = 1 << 9;
    const BFSR_IMPRECISERR: u32 = 1 << 10;
    const BFSR_STKERR: u32 = 1 << 12;
    const UFSR_UNDEFINSTR: u32 = 1 << 16;
    const UFSR_INVSTATE: u32 = 1 << 17;
    const UFSR_UNALIGNED: u32 = 1 << 24;
    const HFSR_VECTTBL: u32 = 1 << 1;

    match () {
        // Both mean the CPU could not push an exception frame: the stack pointer
        // had already left valid memory. Under `flip-link` that is an overflow
        // running off the bottom of RAM.
        _ if cfsr & (MMFSR_MSTKERR | BFSR_STKERR) != 0 => {
            "stack overflow (fault on exception stacking)"
        }
        _ if cfsr & UFSR_UNDEFINSTR != 0 => {
            "undefined instruction (executed non-code — corrupt pointer or smashed return address)"
        }
        _ if cfsr & UFSR_INVSTATE != 0 => {
            "invalid state (bad Thumb bit — corrupt function pointer or return address)"
        }
        _ if cfsr & UFSR_UNALIGNED != 0 => "unaligned access",
        _ if cfsr & BFSR_IMPRECISERR != 0 => {
            "imprecise bus fault (recorded PC is NOT the culprit; the faulting write retired earlier)"
        }
        _ if cfsr & BFSR_PRECISERR != 0 => "precise bus fault (bad data address; see bfar)",
        _ if cfsr & BFSR_IBUSERR != 0 => "bus fault fetching an instruction",
        _ if cfsr & MMFSR_DACCVIOL != 0 => "data access violation (see mmfar)",
        _ if cfsr & MMFSR_IACCVIOL != 0 => "instruction access violation",
        _ if hfsr & HFSR_VECTTBL != 0 => "bus fault reading the vector table",
        _ => "unclassified",
    }
}

/// Record a HardFault's registers into [`FAULT_RECORD`], then reboot — or halt,
/// once [`MAX_CONSECUTIVE_FAULTS`] faults in a row have failed to clear it.
///
/// Overrides `cortex-m-rt`'s default handler, which traps forever: that leaves
/// the node dead *and* loses the evidence.
///
/// Deliberately minimal — volatile reads, relaxed stores, one RTT print. No
/// allocation and no `tracing`, whose dispatcher allocates: the CPU is already
/// in a fault state with an unknown stack, and faulting again escalates to
/// lockup and loses the record.
#[cortex_m_rt::exception]
unsafe fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    // SAFETY: fixed, always-mapped, word-aligned System Control Block addresses,
    // read-only here.
    let (cfsr, hfsr, mmfar, bfar) = unsafe {
        (
            SCB_CFSR.read_volatile(),
            SCB_HFSR.read_volatile(),
            SCB_MMFAR.read_volatile(),
            SCB_BFAR.read_volatile(),
        )
    };

    FAULT_RECORD[IDX_PC].store(ef.pc(), Relaxed);
    FAULT_RECORD[IDX_LR].store(ef.lr(), Relaxed);
    FAULT_RECORD[IDX_CFSR].store(cfsr, Relaxed);
    FAULT_RECORD[IDX_HFSR].store(hfsr, Relaxed);
    FAULT_RECORD[IDX_MMFAR].store(mmfar, Relaxed);
    FAULT_RECORD[IDX_BFAR].store(bfar, Relaxed);
    // Magic last, so a torn write is never mistaken for a complete record.
    FAULT_RECORD[IDX_MAGIC].store(RECORD_MAGIC, Relaxed);

    let count = bump_fault_count();
    rtt_target::rprintln!(
        "hardfault ({}/{}): pc={:#010x} lr={:#010x} cfsr={:#010x} hfsr={:#010x} — {}",
        count,
        MAX_CONSECUTIVE_FAULTS,
        ef.pc(),
        ef.lr(),
        cfsr,
        hfsr,
        cause(cfsr, hfsr)
    );

    if count >= MAX_CONSECUTIVE_FAULTS {
        rtt_target::rprintln!("hardfault: {} consecutive; halting", MAX_CONSECUTIVE_FAULTS);
        halt();
    }
    rtt_target::rprintln!("hardfault: resetting");
    reset()
}

/// Report whatever ended the previous boot — a panic, a HardFault, or neither —
/// and clear it, so a single historical crash does not look like an ongoing one.
///
/// **Call after `wayfinder_log::init()`**, so the records reach the log ring
/// `GetLogs` serves rather than only an RTT channel nobody is attached to —
/// reaching a detached node is the point of retaining them at all.
///
/// At most one of the two is normally set, since either handler resets the board
/// as soon as it has written its own.
pub fn report_retained() {
    report_retained_panic();
    report_retained_hardfault();
}

/// Report a panic retained from the previous boot, if there was one.
fn report_retained_panic() {
    let header = PANIC_HEADER.load(Relaxed);
    if header & PANIC_MAGIC_MASK != PANIC_MAGIC {
        return;
    }
    let len = (header & PANIC_LEN_MASK) as usize;

    let mut buf = [0u8; PANIC_MSG_LEN];
    for (dst, src) in buf.iter_mut().zip(PANIC_MSG.iter()).take(len) {
        *dst = src.load(Relaxed);
    }
    // Falls back to the whole buffer rather than indexing past it: the magic
    // makes a corrupt length unlikely, not impossible.
    let bytes = buf.get(..len).unwrap_or(&buf);

    let detail = match core::str::from_utf8(bytes) {
        Ok(text) => text,
        // Truncating at PANIC_MSG_LEN can split a multi-byte character; keep
        // everything before it rather than losing the whole message.
        Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    };

    error!(detail, "previous boot ended in a panic");

    PANIC_HEADER.store(0, Relaxed);
}

/// Report a HardFault retained from the previous boot, if there was one.
fn report_retained_hardfault() {
    if FAULT_RECORD[IDX_MAGIC].load(Relaxed) != RECORD_MAGIC {
        return;
    }
    let read = |i: usize| FAULT_RECORD[i].load(Relaxed);
    let pc = read(IDX_PC);
    let lr = read(IDX_LR);
    let cfsr = read(IDX_CFSR);
    let hfsr = read(IDX_HFSR);
    let mmfar = read(IDX_MMFAR);
    let bfar = read(IDX_BFAR);

    error!(
        pc = %format_args!("{pc:#010x}"),
        lr = %format_args!("{lr:#010x}"),
        cfsr = %format_args!("{cfsr:#010x}"),
        hfsr = %format_args!("{hfsr:#010x}"),
        mmfar = %format_args!("{mmfar:#010x}"),
        bfar = %format_args!("{bfar:#010x}"),
        cause = cause(cfsr, hfsr),
        "previous boot ended in a hardfault"
    );

    FAULT_RECORD[IDX_MAGIC].store(0, Relaxed);
}
