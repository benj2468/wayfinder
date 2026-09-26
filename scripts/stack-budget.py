#!/usr/bin/env python3
"""Static stack-budget check for a bare-metal embassy image.

Answers, from the linked ELF alone, a question that used to need hardware:
*is this firmware reserving stack it can never give back?*

Under `flip-link` the stack is exactly what `memory.x` leaves below the statics
(`_stack_start` minus `ORIGIN(RAM)`), and every function's frame is the
`sub sp, #N` its prologue executes. Both are static facts.

The gate is on **`TaskStorage::<..>::poll` frames specifically**, not on frames
in general, and the distinction is the whole point. An ordinary function may
reserve a lot and be fine, because it returns. A task's `poll` does not: it
sits underneath the entire body of that task for as long as the task runs, so
every byte it reserves is subtracted from what every frame the task will ever
push has left. A large one is therefore a permanent tax, not a transient peak.

That is exactly how the nRF52840 DK overflowed. A board wrapped
`wayfinder_nrf::node::run` in its own `#[embassy_executor::task]` that awaited
it; `.await`ing a foreign `async fn` makes its future a field of the outer
coroutine, and rustc built that ~62 KB future in a stack temporary and
`memcpy`d it in. The temporary belonged to the wrapper's poll prologue, so it
stayed reserved for the life of the node. 62,720 + the run body's 28,032 +
`Driver::with_capacities`' 26,624 came to 117,376 against a 112,600-byte stack,
ran off the bottom of RAM into the SoftDevice's reserved region, and died as
`NRF_FAULT_ID_APP_MEMACC` with a clean-looking bring-up log.

Verified against the shape it exists for, not just reasoned about: restoring
the pre-fix board wrapper (`#[task] async fn node` awaiting `node::run`) and
re-running this puts 68,320 bytes in that wrapper's `TaskStorage::poll` and
exits 1. The wrapper's coroutine is inlined into its own poll, which is why the
symbol matches.

The blind spot that leaves: when the `#[task]` lives in a *library* (as
`node::run` now does), rustc emits its body as a separate
`___run_task_inner_function0` and the poll is only a trampoline — so in the
fixed image the gated poll frames are 24-100 bytes while the body carries
29,060. That body frame is deliberately not gated: it is a transient per-poll
peak, not a reservation held for the task's life, and it is the same category
as `write_in_place` below. But it does mean this gate bounds the *permanent*
tax only, never total stack depth. Nothing here would catch the ~56 KB chain
(`___run_task_inner_function0` + `Driver::run`) growing until it overflowed;
that needs a call-graph tool or the board's own `stack::report()` high-water.

Note what this deliberately does *not* flag: `UninitCell::write_in_place` still
carries a ~62 KB frame in the fixed image, because that is where the future is
now built — but it is called from a task that completes at boot, so the frame
is gone before the node runs. A blanket per-function cap fails the healthy
image on that frame and teaches everyone to ignore the check. Gating on task
polls separates the permanent reservation from the transient peak.

The budget is a share of the stack rather than a fixed byte count, because a
task poll frame is *overhead*: it holds the coroutine and whatever the body
could not keep in the task pool, while the body's own chain is what does the
work. A task allowed a large share of the region has left the body nothing.
8% is loose enough for a board whose main task legitimately carries a few KB
(the STM32F411 sits at ~5 KB of its 124,748, with a 97 KB body chain on top
that still fits) and roughly 7x tighter than the frame that actually failed.

Set the percentage per board if one has a reason; do not raise it to make a
red pipeline green without first checking the body chain still fits under it.

**The overhead model above does not hold for every board, and the `justfile`
carries the exception.** Where a task body inlines wholesale into its own poll
-- which is what the nRF images do in `--release`, where the compiled poll makes
no calls at all -- the poll frame *is* the body rather than overhead on top of
it, so measuring it against a share meant for overhead compares two different
things. Those boards pass `--task-poll-pct` with the arithmetic written out
beside the recipe. The `24-100` and `29,060` figures quoted above are
`debug`-image measurements from before the gate read `--release`; treat them as
history rather than as what this prints today.

What this does not replace: a worst-case call-graph sum (`cargo-call-stack`),
which needs nightly and resolves the executor's indirect task dispatch badly,
and the board's own `stack::report()` high-water, which is the ground truth but
needs hardware and only speaks after the fact.
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

# A stack reservation: `sub sp, #n`, `sub.w sp, sp, #n`, and Thumb-2's `subw
# sp, sp, #n` -- the 12-bit-immediate encoding the compiler picks when `n` is
# not expressible as a modified immediate (0xae4 is not; 0x3d4 is). Missing a
# form is not a harmless blind spot: that frame reads as zero bytes and passes
# any budget, which is how a 2,788-byte and two 3,388-byte task polls went
# unmeasured. `scripts/tests/test_stack_budget.py` pins each form.
FRAME_RE = re.compile(r"\bsubw?(?:\.w)?\s+sp, (?:sp, )?#(0x[0-9a-f]+|\d+)\b")
SYMBOL_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")
ORIGIN_RE = re.compile(r"^\s*RAM\s*:\s*ORIGIN\s*=\s*([^,]+),\s*LENGTH", re.MULTILINE)

# `TaskStorage::<F>::poll`, in the v0 mangling embassy-executor is built with.
TASK_POLL_RE = re.compile(r"TaskStorage.*4poll")


def ram_origin(memory_x):
    """`ORIGIN(RAM)` as written in `memory.x`, before flip-link rewrites it.

    Read from the board's linker script rather than the final image on purpose:
    by the last link flip-link has set `ORIGIN(RAM)` equal to `_stack_start`,
    which would collapse the measured region to nothing. Same reason
    `wayfinder_nrf::stack::paint` takes the floor as an argument.
    """
    with open(memory_x) as f:
        match = ORIGIN_RE.search(f.read())
    if not match:
        sys.exit(f"{memory_x}: no RAM ORIGIN found")
    expr = match.group(1).strip()
    if not re.fullmatch(r"[0-9a-fx+\-*\s]+", expr, re.IGNORECASE):
        sys.exit(f"{memory_x}: unexpected RAM ORIGIN expression {expr!r}")
    return eval(expr)


def find_tool(name):
    """Locate `llvm-<name>`, preferring the one shipped with this toolchain.

    `llvm-tools-preview` puts them under the rustc sysroot, which is what the
    CI image installs; `cargo-binutils`' `rust-<name>` shims are not there and
    are only a fallback for a dev box that has them on `PATH`.
    """
    try:
        sysroot = subprocess.run(
            ["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True
        ).stdout.strip()
        for path in glob.glob(f"{sysroot}/lib/rustlib/*/bin/llvm-{name}"):
            return path
    except (OSError, subprocess.CalledProcessError):
        pass
    for candidate in (f"llvm-{name}", f"rust-{name}"):
        if shutil.which(candidate):
            return candidate
    sys.exit(f"no llvm-{name} found: install the llvm-tools-preview component")


def run_tool(tool, *args):
    return subprocess.run(
        [tool, *args], capture_output=True, text=True, check=True
    ).stdout


def symbols(nm, elf, wanted):
    """Addresses of the linker symbols bounding the stack and the statics."""
    found = {}
    for line in run_tool(nm, elf).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in wanted:
            found[parts[2]] = int(parts[0], 16)
    missing = wanted - found.keys()
    if missing:
        sys.exit(
            f"{elf}: missing {', '.join(sorted(missing))}; is this a cortex-m-rt image?"
        )
    return found


def stack_region(nm, elf, memory_x):
    """The bytes the stack actually has, and which linker layout produced them.

    Two layouts, and the image is asked rather than a build flag — the same
    check `wayfinder_nrf::stack::paint` makes, for the same reason: dropping
    the `linker = "flip-link"` line is a one-line change nothing else notices.

    With `flip-link` the statics sit above the stack, so the stack runs from
    `_stack_start` down to the board's true `ORIGIN(RAM)` — which has to come
    from `memory.x`, since by the final link flip-link has rewritten
    `ORIGIN(RAM)` to equal `_stack_start`. Without it, `cortex-m-rt`'s default
    puts the stack at the top of RAM growing down toward `.bss`, so the room it
    has is `_stack_start` minus `__ebss`.
    """
    addrs = symbols(nm, elf, {"_stack_start", "__sbss", "__ebss"})
    top = addrs["_stack_start"]
    if addrs["__sbss"] >= top:
        return top, top - ram_origin(memory_x), "flip-link"
    return top, top - addrs["__ebss"], "cortex-m-rt default"


def frames(objdump, elf):
    """Each function's stack reservations summed, largest first.

    Not strictly the prologue: a prologue may split its reservation across two
    `sub sp` instructions (the STM32 image does — `#0x17a00` then `#0x1e4`), so
    every match in the function is accumulated. A later, non-prologue `sub sp`
    is therefore counted too, which over-states rather than under-states — the
    safe direction for a gate.
    """
    return parse_frames(run_tool(objdump, "-d", "--no-show-raw-insn", elf))


def parse_frames(disassembly):
    """`frames` on an `objdump -d --no-show-raw-insn` listing already in hand,
    so the parser is testable without an ELF or a toolchain."""
    found, symbol = {}, "<unknown>"
    for line in disassembly.splitlines():
        sym = SYMBOL_RE.match(line)
        if sym:
            symbol = sym.group(1)
            continue
        hit = FRAME_RE.search(line)
        if hit:
            # A prologue can split its reservation across two `sub`s.
            found[symbol] = found.get(symbol, 0) + int(hit.group(1), 0)
    return sorted(found.items(), key=lambda kv: -kv[1])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf")
    ap.add_argument("--memory-x", required=True)
    ap.add_argument("--objdump", help="defaults to the toolchain's llvm-objdump")
    ap.add_argument("--nm", help="defaults to the toolchain's llvm-nm")
    ap.add_argument(
        "--task-poll-pct",
        type=float,
        default=8.0,
        help="share of the stack one task's poll frame may reserve (percent)",
    )
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()
    # cargo-binutils shims resolve a relative path against the workspace root,
    # not the caller's cwd.
    args.elf = os.path.abspath(args.elf)
    objdump = args.objdump or find_tool("objdump")
    nm = args.nm or find_tool("nm")

    top, region, layout = stack_region(nm, args.elf, args.memory_x)
    budget = int(region * args.task_poll_pct / 100)
    ranked = frames(objdump, args.elf)
    task_polls = [(sym, n) for sym, n in ranked if TASK_POLL_RE.search(sym)]

    print(f"{os.path.basename(args.elf)}")
    print(f"  stack region     {region} bytes, top 0x{top:08x} ({layout})")
    print(
        f"  task-poll budget {budget} bytes per task ({args.task_poll_pct:g}% of region)\n"
    )
    print("  largest frames overall (informational):")
    for symbol, size in ranked[: args.top]:
        print(f"    {size:>7}  {symbol[:88]}")

    if not task_polls:
        sys.exit("\nno TaskStorage::poll symbols found; is this an embassy image?")

    print(f"\n  task polls ({len(task_polls)}):")
    over = []
    for symbol, size in task_polls:
        bad = size > budget
        over.append((symbol, size)) if bad else None
        print(f"    {size:>7}  {symbol[:88]}{'   <-- OVER BUDGET' if bad else ''}")

    if over:
        print(
            f"\nFAIL: {len(over)} task poll frame(s) over budget. A task's poll frame is "
            f"held for the task's whole life, so this is stack no other frame can use.\n"
            f"The usual cause is a `#[task]` that `.await`s another `async fn`: its "
            f"future is built in a stack temporary and copied in."
        )
        return 1
    print(f"\nOK: largest task poll frame {task_polls[0][1]} bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
