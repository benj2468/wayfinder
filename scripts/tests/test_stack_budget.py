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


# --- `memory.x` against the chip -------------------------------------------
#
# The frame gate measures against the region `memory.x` declares, so a wrong
# `memory.x` makes every number it prints wrong while it still prints OK. The
# STM32F411 image shipped exactly that: the nRF52840's map (flash at the
# 0x0 boot alias, 256 KiB of RAM on a 128 KiB part), a stack top past the end
# of real RAM, and a green gate (design 25 §2.2).

F411_BROKEN_MEMORY_X = """
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1016K
  RAM : ORIGIN = 0x20000000, LENGTH = 256K
}
"""

DONGLE_MEMORY_X = """
MEMORY
{
  /* SoftDevice S140 and the bootloader sit around this. */
  FLASH : ORIGIN = 0x00001000, LENGTH = 884K
  RAM : ORIGIN = 0x20000008, LENGTH = 256K - 8
}
"""


def test_memory_regions_reads_origin_and_length_expressions():
    assert stack_budget.memory_regions(DONGLE_MEMORY_X) == {
        "FLASH": (0x1000, 884 * 1024),
        "RAM": (0x20000008, 256 * 1024 - 8),
    }


def test_chip_region_spec_accepts_k_and_m_suffixes():
    assert stack_budget.parse_chip_region("0x20000000:64K") == (0x20000000, 64 * 1024)
    assert stack_budget.parse_chip_region("0x0:1M") == (0, 1024 * 1024)


def test_region_inside_the_chip_has_no_errors():
    regions = stack_budget.memory_regions(DONGLE_MEMORY_X)
    assert (
        stack_budget.region_errors("RAM", regions["RAM"], (0x20000000, 256 * 1024))
        == []
    )


def test_f411_broken_ram_is_refused():
    """256 KiB declared on the F411's 128 KiB."""
    regions = stack_budget.memory_regions(F411_BROKEN_MEMORY_X)
    errors = stack_budget.region_errors("RAM", regions["RAM"], (0x20000000, 128 * 1024))
    assert len(errors) == 1
    assert "RAM" in errors[0] and "0x20040000" in errors[0]


def test_f411_broken_flash_origin_is_refused():
    """Flash at the 0x0 boot alias, on a part whose flash is at 0x08000000."""
    regions = stack_budget.memory_regions(F411_BROKEN_MEMORY_X)
    errors = stack_budget.region_errors(
        "FLASH", regions["FLASH"], (0x08000000, 512 * 1024)
    )
    assert errors and "FLASH" in errors[0]


def test_stack_top_past_the_chip_is_refused():
    """The symptom the F411 image printed and the gate let through."""
    assert stack_budget.stack_top_errors(0x20040000, (0x20000000, 128 * 1024))
    assert stack_budget.stack_top_errors(0x20020000, (0x20000000, 128 * 1024)) == []
