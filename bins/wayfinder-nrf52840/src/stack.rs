//! Stack high-water measurement, for answering "did this board overflow its
//! stack?" without having to catch the overflow happening.
//!
//! The technique is stack painting: fill the unused stack with a known word at
//! boot ([`paint`]), then later find the deepest word that no longer holds it
//! ([`high_water`]). Everything below that point was written by some call frame
//! or exception frame at some moment since boot, even though the stack has long
//! since unwound past it. That makes the *peak* depth observable from a node
//! that is sitting there idle — which is the whole point, because the peak is
//! reached during a burst (a management session, a radio event storm) that is
//! over by the time anyone asks.
//!
//! This is a diagnostic, not a guard. [`crate::HardFault`] is what catches an
//! overflow that actually happens; this is what tells you how close the board
//! runs to the edge *before* one does.
//!
//! # This module is unsafe without `flip-link`, and knows it
//!
//! Painting means writing every word between the bottom of the stack and the
//! current stack pointer. Whether that region is *stack* depends entirely on the
//! memory layout:
//!
//! - **With `flip-link`** (selected in `.cargo/config.toml`) the stack is placed
//!   at the bottom of RAM and the statics above it, so everything below the
//!   stack pointer is unused stack. Painting it is correct.
//! - **Without it** the stack starts at the top of RAM and grows *down* into
//!   `.uninit`, then `.bss`, then `.data`. Everything below the stack pointer is
//!   live static state — the heap, the router, `PANIC_GUARD`. Painting it would
//!   destroy the program.
//!
//! So [`paint`] detects the layout at runtime and does nothing unless it can
//! prove the first case holds. The proof is [`flip_link_active`]: under
//! `flip-link` the statics sit *above* the initial stack pointer, and in the
//! default layout they sit below it, so comparing `__sbss` against
//! `_stack_start` distinguishes the two with no build-time flag to keep in sync.
//!
//! That check is not defensive programming for its own sake. Dropping the
//! `linker =` line from `.cargo/config.toml` is a one-line change that looks
//! entirely unrelated to this file, and the failure it would otherwise cause —
//! `.bss` overwritten with a pattern word during boot — would present as
//! arbitrary corruption with no obvious connection to stack measurement. Failing
//! closed costs one comparison.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use tracing::debug;
use tracing::warn;

/// Base address of the SoftDevice-adjusted RAM region, and therefore the lowest
/// address the stack can occupy once `flip-link` has moved it to the bottom.
///
/// Must equal `memory.x`'s `RAM` `ORIGIN` — `0x20000000` plus the 13112 bytes
/// reserved for the SoftDevice's own state. Kept as a const here for the same
/// reason `DURABLE_STORE_BASE` is in `main.rs`: the linker script is not
/// readable from Rust, so the one number has to be repeated and kept in sync.
/// If the SoftDevice's RAM requirement changes, both move together.
const RAM_ORIGIN: usize = 0x2000_0000 + 13112;

/// The word [`paint`] fills unused stack with.
///
/// Chosen to be conspicuous in a memory dump and unlikely to occur naturally in
/// stack data: not zero (fresh RAM and cleared frames are full of it), not a
/// plausible pointer into this chip's flash or RAM, and not a repeating byte
/// that a partial word write could reproduce by accident.
const PAINT_WORD: u32 = 0xDEAD_BEEF;

/// Bytes below the stack pointer that [`paint`] leaves alone.
///
/// Painting walks up to the current stack pointer, but the stack pointer is not
/// a hard floor: an exception taken mid-paint pushes its frame *below* it (32
/// bytes, or 104 with the FPU context the `thumbv7em-none-eabihf` target can
/// stack). Overwriting that frame would corrupt the return of an interrupt that
/// happened to land during boot — a rare, timing-dependent fault, which is
/// precisely the kind this module exists to eliminate rather than create. Half a
/// kilobyte is far more than any single frame needs and costs only a slight
/// underestimate of the painted region.
const PAINT_MARGIN_BYTES: usize = 512;

/// Free stack below which [`report`] escalates from `debug!` to `warn!`.
///
/// A node this close to the floor has not failed, but it is one deeper
/// interrupt-handler nesting away from doing so, and that is worth an operator's
/// attention before it becomes a fault.
const LOW_HEADROOM_BYTES: usize = 2048;

/// Whether [`paint`] ran and the region below the high-water mark can be
/// trusted to hold [`PAINT_WORD`].
///
/// An ordinary `static` (not `.uninit` like `PANIC_GUARD`): this describes only
/// the current boot, and a reset invalidates it, so being zeroed at startup is
/// exactly the wanted behaviour.
static PAINTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// Start of `.bss`, emitted by `cortex-m-rt`'s linker script. Only its
    /// address is meaningful.
    static __sbss: u32;
    /// The initial stack pointer — the top of the stack, since it grows down.
    /// `cortex-m-rt` puts this at the end of RAM; `flip-link` rewrites it to sit
    /// just above the stack region it carves out at the bottom. Only its address
    /// is meaningful.
    static _stack_start: u32;
}

/// Address of the top of the stack (exclusive): the value the stack pointer is
/// initialised to at reset.
fn stack_top() -> usize {
    (&raw const _stack_start) as usize
}

/// Address of the start of `.bss`, used only to tell the two possible memory
/// layouts apart. See [`flip_link_active`].
fn bss_start() -> usize {
    (&raw const __sbss) as usize
}

/// Whether the binary was linked with `flip-link`, i.e. whether the stack sits
/// below the statics.
///
/// `flip-link` relocates the statics to start above the stack region, so
/// `__sbss` lands *above* the initial stack pointer; in `cortex-m-rt`'s default
/// layout the stack starts at the end of RAM and every static is below it. The
/// two orderings cannot both hold, so the comparison is a reliable test of which
/// layout was produced — and it reads the actual linked image rather than a
/// build flag that could disagree with it.
fn flip_link_active() -> bool {
    bss_start() >= stack_top()
}

/// Total bytes available to the stack, or `None` under a layout where this
/// module cannot say.
fn stack_size() -> Option<usize> {
    flip_link_active().then(|| stack_top().saturating_sub(RAM_ORIGIN))
}

/// Fill the unused stack with [`PAINT_WORD`], so [`high_water`] can later find
/// how deep execution has gone.
///
/// **Call this as the first thing in `main`**, before the allocator, the
/// tracing subscriber, or any peripheral init. Two reasons: the measurement
/// covers only what happens after it runs, so anything earlier is invisible;
/// and it must run while the stack is at its shallowest, since everything from
/// the current stack pointer *up* is left unpainted and therefore counted as
/// used.
///
/// Does nothing — and reports nothing, having no way to log this early — if
/// [`flip_link_active`] is false. See the module docs for why that check is
/// load-bearing.
pub fn paint() {
    if !flip_link_active() {
        return;
    }

    let sp = cortex_m::register::msp::read() as usize;
    let ceiling = sp.saturating_sub(PAINT_MARGIN_BYTES);

    // A stack pointer at or below the floor means the layout is not what
    // `flip_link_active` claimed; leave memory alone rather than write outside
    // the region this function reasoned about.
    if ceiling <= RAM_ORIGIN {
        return;
    }

    let mut addr = RAM_ORIGIN;
    while addr < ceiling {
        // SAFETY: `addr` is within `[RAM_ORIGIN, sp - PAINT_MARGIN_BYTES)`,
        // which under the `flip_link_active` layout is stack below the current
        // stack pointer — memory no live frame owns. It is word-aligned because
        // `RAM_ORIGIN` is (13112 = 4 * 3278) and the stride is 4.
        unsafe { (addr as *mut u32).write_volatile(PAINT_WORD) };
        addr += size_of::<u32>();
    }

    PAINTED.store(true, Ordering::Relaxed);
}

/// Peak stack usage since [`paint`], as `(used_bytes, total_bytes)`.
///
/// Returns `None` if painting did not run, in which case unpainted memory would
/// be indistinguishable from memory a frame had written.
///
/// Scans up from the bottom of the stack for the first word that no longer holds
/// [`PAINT_WORD`]; everything above it has been touched. The scan is
/// deliberately from the bottom, so it stops at the deepest excursion and its
/// cost is proportional to the *free* stack rather than the whole region.
///
/// Two ways this can read low, both erring towards under-reporting danger rather
/// than over-reporting it: a frame that happened to write [`PAINT_WORD`] itself
/// is counted as untouched, and a frame that was pushed but never written to
/// (stack allocated and left uninitialised) leaves the paint intact.
pub fn high_water() -> Option<(usize, usize)> {
    if !PAINTED.load(Ordering::Relaxed) {
        return None;
    }
    let total = stack_size()?;

    let mut addr = RAM_ORIGIN;
    let top = stack_top();
    while addr < top {
        // SAFETY: `addr` is within `[RAM_ORIGIN, stack_top())`, the stack
        // region established by `flip_link_active`, and word-aligned as in
        // `paint`. A volatile read so the scan is not hoisted or elided.
        if unsafe { (addr as *const u32).read_volatile() } != PAINT_WORD {
            break;
        }
        addr += size_of::<u32>();
    }

    Some((top.saturating_sub(addr), total))
}

/// Log the current stack high-water mark.
///
/// `debug!` normally — this is developer-facing state, not an operator event —
/// but `warn!` once free space falls under [`LOW_HEADROOM_BYTES`], which is a
/// capacity problem an operator can act on.
pub fn report() {
    let Some((used, total)) = high_water() else {
        return;
    };
    let free = total.saturating_sub(used);
    if free < LOW_HEADROOM_BYTES {
        warn!(used, free, total, "stack headroom low");
    } else {
        debug!(used, free, total, "stack high water");
    }
}
