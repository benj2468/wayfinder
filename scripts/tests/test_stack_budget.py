"""The frame parser behind `just stack-budget`.

The gate is only as good as what it recognises as a stack reservation: a
prologue form it misses reads as a zero-byte frame, and a zero-byte frame
passes any budget. Each case here is an instruction form a real board image
emits.
"""

import importlib.util
from pathlib import Path

# `stack-budget.py` is a script with a hyphenated name, not a module.
_SPEC = importlib.util.spec_from_file_location(
    "stack_budget", Path(__file__).resolve().parent.parent / "stack-budget.py"
)
stack_budget = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stack_budget)


def disasm(symbol, *instructions):
    """An `llvm-objdump -d --no-show-raw-insn` listing of one function."""
    lines = [f"0800dcdc <{symbol}>:"]
    lines += [f" 800dcdc:      \t{insn}" for insn in instructions]
    return "\n".join(lines)


def test_sub_w_immediate_is_a_frame():
    text = disasm("f", "push\t{r4, r5, r6, r7, lr}", "sub.w\tsp, sp, #0x3d4")
    assert stack_budget.parse_frames(text) == [("f", 0x3D4)]


def test_subw_twelve_bit_immediate_is_a_frame():
    """Thumb-2 `SUBW` — the encoding for an immediate the modified-immediate
    form cannot express, e.g. 0xae4. The STM32WL55 relay's main task poll
    reserves 2,788 bytes this way, and the nRF boards' main task 3,388; both
    used to be read as zero."""
    text = disasm("poll", "push.w\t{r8, r9, r10, r11}", "subw\tsp, sp, #0xae4")
    assert stack_budget.parse_frames(text) == [("poll", 0xAE4)]


def test_split_reservation_is_summed():
    text = disasm("big", "sub.w\tsp, sp, #0x17a00", "sub\tsp, #0x1e4")
    assert stack_budget.parse_frames(text) == [("big", 0x17A00 + 0x1E4)]


def test_sp_relative_address_is_not_a_frame():
    """`sub r0, sp, #n` computes an address below `sp`; it reserves nothing."""
    text = disasm("g", "sub.w\tr0, sp, #0x40")
    assert stack_budget.parse_frames(text) == []


def test_largest_frame_first_across_functions():
    text = "\n".join(
        [
            disasm("small", "sub\tsp, #0x10"),
            disasm("large", "subw\tsp, sp, #0x800"),
        ]
    )
    assert stack_budget.parse_frames(text) == [("large", 0x800), ("small", 0x10)]
