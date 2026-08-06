//! Stack high-water measurement, for answering "did this board come close to
//! overflowing its stack?" without having to catch the overflow happening.
//!
//! Stack painting: fill the unused stack with [`PAINT_WORD`] at boot
//! ([`paint`]), then find the deepest word that no longer holds it. That makes
//! the *peak* readable from an idle node, long after the burst that caused it.
//! A diagnostic, not a guard — [`crate::fault`] catches an overflow that
//! actually happens.
//!
//! **Painting is memory corruption without `flip-link`**, which puts the stack
//! below the statics; in `cortex-m-rt`'s default layout the same writes land in
//! `.uninit`, `.bss` and `.data`. So [`paint`] proves the layout at runtime,
//! from `__sbss` against `_stack_start`, rather than trusting a build flag —
//! dropping the `linker =` line is a one-line change nothing else here would
//! notice, presenting as arbitrary `.bss` corruption during boot.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::Relaxed;

use embassy_time::Duration;
use embassy_time::Timer;
use tracing::debug;
use tracing::warn;

/// The word [`paint`] fills unused stack with: conspicuous in a memory dump,
/// not zero (fresh RAM and cleared frames are full of it), and not a plausible
/// pointer into this chip's flash or RAM.
const PAINT_WORD: u32 = 0xDEAD_BEEF;

/// Bytes below the stack pointer [`paint`] leaves alone. The stack pointer is
/// not a hard floor: an exception taken mid-paint stacks its frame below it (up
/// to 104 bytes with this target's FPU context).
const PAINT_MARGIN_BYTES: usize = 512;

/// Free stack below which [`report`] escalates from `debug!` to `warn!`. A node
/// this close to the floor has not failed, but it is one deeper interrupt
/// nesting away from doing so.
const LOW_HEADROOM_BYTES: usize = 2048;

/// Interval between [`watch`]'s reports. The measurement is a peak-since-boot,
/// so a longer interval cannot miss a burst — only delay noticing it.
const REPORT_INTERVAL_SECS: u64 = 60;

/// The board's RAM floor as handed to [`paint`], or 0 if it never ran — in
/// which case nothing can be trusted to hold [`PAINT_WORD`]. An ordinary
/// `static`, unlike [`crate::fault`]'s: this describes only the current boot.
static FLOOR: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    /// Start of `.bss`. Only its address is meaningful.
    static __sbss: u32;
    /// The initial stack pointer — the top of the stack, since it grows down.
    /// `flip-link` rewrites this to sit just above the stack region it carves
    /// out at the bottom of RAM. Only its address is meaningful.
    static _stack_start: u32;
}

/// Address the stack pointer is initialised to at reset (exclusive top).
fn stack_top() -> usize {
    (&raw const _stack_start) as usize
}

/// Whether the image was linked with `flip-link`, i.e. whether the stack sits
/// below the statics. The two possible orderings of `__sbss` and `_stack_start`
/// cannot both hold, so this reads the actual linked image rather than a build
/// flag that could disagree with it.
fn flip_link_active() -> bool {
    (&raw const __sbss) as usize >= stack_top()
}

/// Fill the unused stack with [`PAINT_WORD`] so [`high_water`] can later find
/// how deep execution has gone.
///
/// **Call as the first thing in `main`**: the measurement covers only what
/// happens afterwards, and everything from the stack pointer up is left
/// unpainted and therefore counted as used.
///
/// `ram_floor` is the board's true `ORIGIN(RAM)`, where the stack bottoms out.
/// It must be handed in, not read from a linker symbol: `flip-link` rewrites
/// the `MEMORY` block, so by the final link `ORIGIN(RAM)` equals
/// `_stack_start` and a symbol defined from it collapses the region to nothing.
/// The board's `memory.x` is the only place the real number exists.
///
/// Does nothing, and cannot report it — there is no logging this early — if the
/// layout is not the one the module docs require.
pub fn paint(ram_floor: usize) {
    if !flip_link_active() {
        return;
    }
    let floor = ram_floor;
    let ceiling = (cortex_m::register::msp::read() as usize).saturating_sub(PAINT_MARGIN_BYTES);

    // A stack pointer at or below the floor means the layout is not what
    // `flip_link_active` claimed; leave memory alone rather than write outside
    // the region this function reasoned about.
    if ceiling <= floor {
        return;
    }

    let mut addr = floor;
    while addr < ceiling {
        // SAFETY: `addr` is within `[ram_origin(), msp - PAINT_MARGIN_BYTES)`,
        // which under this layout is stack below the current stack pointer —
        // memory no live frame owns. Word-aligned because `ORIGIN(RAM)` is and
        // the stride is 4.
        unsafe { (addr as *mut u32).write_volatile(PAINT_WORD) };
        addr += size_of::<u32>();
    }

    FLOOR.store(floor, Relaxed);
}

/// Peak stack usage since [`paint`], as `(used_bytes, total_bytes)`, or `None`
/// if painting did not run — in which case unpainted memory would be
/// indistinguishable from memory a frame had written.
///
/// Scans up from the bottom, so it costs time proportional to the *free* stack
/// rather than the whole region. Two ways it reads low, both under-reporting
/// danger: a frame that wrote [`PAINT_WORD`] itself, and one pushed but never
/// written to, each count as untouched.
pub fn high_water() -> Option<(usize, usize)> {
    let floor = match FLOOR.load(Relaxed) {
        0 => return None,
        floor => floor,
    };
    let top = stack_top();
    let mut addr = floor;
    while addr < top {
        // SAFETY: `addr` is within the stack region established by
        // `flip_link_active`, and word-aligned as in `paint`. Volatile so the
        // scan is not hoisted or elided.
        if unsafe { (addr as *const u32).read_volatile() } != PAINT_WORD {
            break;
        }
        addr += size_of::<u32>();
    }
    Some((top.saturating_sub(addr), top.saturating_sub(floor)))
}

/// Log the current stack high-water mark: `debug!` normally, `warn!` once free
/// space falls under [`LOW_HEADROOM_BYTES`].
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

/// Periodically [`report`] how close the board has come to exhausting its stack.
///
/// Its own task rather than folded into the mesh loop, so the reading keeps
/// coming even if that loop is wedged — a stack problem being exactly the kind
/// of fault that would wedge it.
#[embassy_executor::task]
pub async fn watch() -> ! {
    loop {
        Timer::after(Duration::from_secs(REPORT_INTERVAL_SECS)).await;
        report();
    }
}
