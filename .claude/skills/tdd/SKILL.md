---
name: tdd
description: Use before writing implementation code for any new or changed behavior in wayfinder — e.g. "add support for X", "implement Y", "make Z do W". This project develops test-first; also covers this repo's unit-test conventions (u8 for generic containers, a mac(n) helper for concrete Mac tests, assert_invariants() for stateful structures).
---

# Test-driven development in wayfinder

## Process

1. **Write the test first.** Express the desired API and outcome in the
   `#[cfg(test)]` module at the bottom of the relevant source file (or the
   appropriate integration-test crate). Run it and confirm it fails — either
   at compile time (the API doesn't exist yet) or at runtime (the behavior
   isn't implemented). That failing "red" state is the specification.
2. **Stop there unless told otherwise.** Do not pair the implementation with
   the failing test in the same change unless the user explicitly asks for
   both. The failing test is its own checkpoint — it captures intent so it can
   be reviewed independently of the implementation. If unsure whether the user
   wants both in one pass, ask rather than assume.
3. **Implement the minimum** needed to turn the test green.
4. **Refactor** with the test as the safety net.

## Unit-test conventions (apply regardless of where in the TDD cycle you are)

- All non-trivial logic needs unit tests: data structures with internal
  invariants (LRU caches, routing tables, free-slot stacks), protocol state
  machines and routing algorithms, and edge cases (empty, single-element,
  at-capacity, eviction).
- Generic container tests (`IdentTable`, `LinkQualityTable`, `Switch`): use
  `u8` as the identifier type — it implements `MeshIdentifier`.
- Engine/router/wire tests, which are concrete over `Mac`: use a
  `fn mac(n: u8) -> Mac { Mac([0,0,0,0,0,n]) }` helper to build node addresses
  from compact literals, rather than spelling out six-byte arrays.
- When a data structure has non-trivial invariants, add a `#[cfg(test)]`
  `assert_invariants()` helper and call it after each operation in the
  relevant tests.
