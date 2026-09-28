# Design: which build is this node running?

**Status:** Implemented — landed on `main` in `85dd963`. §9 records what the
implementing session decided.

Owns GitLab #59.

## 1. Scope

**In play:**

- `libs/wayfinder-version` — **new**. A zero-dependency `no_std` crate whose
  `build.rs` resolves a build identity and bakes it into consts.
- `libs/wayfinder-protos` — a `BuildInfo` message and `BuildSource` enum;
  `NodeInfo.build_info` at field 7; `handle_router_read` fills it.
- Renderers: `bins/wayfinder-ctl/src/output.rs`, `bins/wayfinder-tui/src/ui.rs`
  (Overview), `bins/wayfinder-web/src/components/overview.rs` (Overview),
  `libs/wayfinder-hil/src/diagnostics.rs`.
- `--version` on the five host binaries; a startup `info!` on the host node and
  both board bring-up paths (`libs/wayfinder-nrf/src/node.rs`, shared by the
  two nRF boards, and `bins/wayfinder-stm32f411/src/main.rs`).
- Build-environment injection: `flake.nix` + `nix/default.nix`,
  `containers/Dockerfile`, `.github/workflows/ci.yml`'s `deploy` job.
- `libs/wayfinder-hil/tests/smoke.rs` — a staleness assertion.

**Explicitly not touched:**

- **`RouterReads`, `RouterAdapter`, `RouterView`, and every mock provider.** §5.2
  argues why the build identity deliberately does *not* travel the usual
  provider path, which is the one design decision here a reviewer should push
  on.
- **The routing core, the wire format on the mesh, the certificate format.**
  Nothing a *node sends to another node* changes. This is a management-API field.
- **Crate versions and release tags.** Every crate stays `0.1.0` and no tag is
  created; §7 records the convention this consumes but does not establish.
- **`libs/wayfinder-py`.** Not in the dependency graph — it does not depend on
  `wayfinder-protos`, and its lockfile is unchanged.

## 2. Motivation

A node cannot be asked which code it is executing.

The ticket came out of an `unauthenticated_traffic` alarm between the compose
node and a USB-attached nRF52840 dongle. A live-mesh auth question usually turns
on whether *both* ends carry a given fix — here the rebooted-peer replay-counter
re-anchor (`70d5f8e`). Answering "does the board have that commit?" meant reading
the mtime of a `.hex` file and then asking the operator to confirm. On a board
flashed weeks ago by someone else, that is not even a guess.

The gap is worst exactly where it matters most. A bare-metal board has no
filesystem to inspect, no package manager, and often no probe attached: the
management API is the only thing that *can* answer, and it could not. A
`wayfinder-tap` container built from `:nightly` has the same problem for the same
reason — nothing in the image records what went into it.

Before this change the repo had **no build metadata at all** beyond clap's bare
`version,` shorthand on two binaries — which expands to `CARGO_PKG_VERSION`, and
every crate here is pinned at `0.1.0`. No `vergen`/`built`/`git-version`, and no
git capture anywhere. `wayfinderctl --version` printed `0.1.0`, which
identifies nothing; `wayfinder-tap`, `wayfinder-tui` and `wayfinder-web` had no
`--version` at all.

## 3. Goals / non-goals

**Goals**

- A node reports the build it is running, over the management API, host and
  board alike.
- Correct in all four build environments: a developer tree, `nix build`, the
  container build, GitHub Actions.
- A **tagged** commit reports its tag. For a release the tag is the identity;
  the hash under it is an implementation detail.
- Never fail a build because git is unavailable.

**Non-goals**

- **Establishing a release-tag convention.** This consumes tags; it does not
  mint one. See §7.
- **A build timestamp.** It would break Nix reproducibility, and the hash is the
  part that identifies *what code*. A commit *date* would be reproducible and is
  a cheap later addition if wanted.
- **A flash-fit CI gate.** None exists today (`build-stack-budget` checks RAM
  only). §8 measures the cost; building the gate is a follow-up.

## 4. Design: resolving the identity

`libs/wayfinder-version/build.rs` is a thin collector. All the rules live in
`src/resolve.rs`, a pure function from raw strings to a decision, which the
build script pulls in with `include!` so the script and the library cannot
drift. That file is where the unit tests are, because a `build.rs` cannot be
unit-tested.

Resolution is a strict three-tier fallthrough:

| Tier | Source | When it fires | Trust |
| --- | --- | --- | --- |
| 1 | `$WAYFINDER_BUILD_VERSION` + `$WAYFINDER_BUILD_COMMIT` | Nix, container, CI | Exact by construction |
| 2 | `git describe` / `git rev-parse` in the source tree | A developer tree | Best-effort (see §6.1) |
| 3 | Neither | A source archive | Reports `unknown` |

The resulting strings:

```
tagged HEAD       -> v0.4.0
tag + 12 commits  -> v0.4.0-12-g35dcaee
no tag            -> 35dcaee
modified tree     -> ...-dirty
```

Two details in the git invocation are load-bearing rather than incidental:

- **`--match 'v[0-9]*'`.** Without it, `describe` reports whatever tag is
  nearest — and this repo's only tag today is
  `backup/pre-rebase-expired-invite`, which would become the reported version of
  every node built from `main`.
- **`git -C <manifest dir>`**, not stat'ing `.git/`. In a worktree `.git` is a
  *file* pointing elsewhere, and worktrees are where this repo's development
  happens. The same applies to the rerun-if-changed paths, which come from
  `git rev-parse --git-path` for the same reason.

`dirty` and `source` reach the library as `rustc-cfg` rather than strings, so
they are a `bool` and an enum in const context with nothing parsed at runtime.

## 5. Design: reporting it

### 5.1 The wire

`NodeInfo` gains field 7, a nested `BuildInfo { version, commit, dirty, source }`.
Nested rather than four scalars so a consumer can branch on `dirty` without
parsing a string, and so "this node does not report a build" stays distinct from
"this node reports an unknown build" — the field is `Option` on the Rust side and
absent for a node too old to carry it.

`source` is on the wire because the tiers differ in how much they can be
trusted, and a consumer deciding whether to believe `dirty` needs to know which
one answered.

### 5.2 Why not a `RouterReads` method

Every other `NodeInfo` field is read off a provider. This one is filled directly
from the const in `handle_router_read`, and that is a deliberate departure.

A build identity is a compile-time property of **the binary answering the
request**, not router state. Routing it through the trait would mean a new trait
method, ~10 impls (mostly test mocks) each returning the same const, and three
`with_*` injection sites — in `router_handle`, the tokio driver and the embedded
driver. That buys no flexibility, because there is no per-node value to inject,
and it adds a failure mode: a shell that forgets to inject would report nothing.
Filling it centrally means **a node cannot be built that fails to report its
build**, which is the property the feature actually needs.

The alternative considered and rejected was
`RouterAdapter::with_build_version(...)`, matching the existing
`with_clock_trusted` pattern. It is the more conventional shape here and a
reviewer may prefer it; the argument above is why it was not taken.

The cost is that `wayfinder-version` sits under `wayfinder-protos`, so the whole
workspace recompiles when HEAD moves or the tree first goes dirty. The narrow
`rerun-if-changed` set keeps that to once per commit rather than once per edit.

### 5.3 Where it surfaces

`wayfinderctl node-info` (human + JSON), the TUI Overview pane, the web Overview
tab, HIL diagnostics, `--version` on all five host binaries, and a startup
`info!` on every node — the last so the build is in `GetLogs` and in the
RTT/console transcript even for a node nobody queried, and before any bring-up
that might halt.

Each renderer calls out a modified tree **in words**. `-dirty` at the end of a
hash is easy to skim past, and it is the normal state of a bench flash — the
ticket makes that point explicitly.

## 6. Correctness and edge cases

### 6.1 The dirty bit can lag by one build

Cargo reruns a build script on file *modification*. An edit to a tracked file
that never touches the git index can leave `dirty` stale until something
refreshes the index (`git status`, `git add`, a commit). `vergen` and
`git-version` carry the same caveat.

This is not papered over: it is documented on `watch_git_state`, and it is why
`source` is reported. `Injected` identities — every release build — are exact;
`Git` ones are best-effort. The failure mode is also the safe direction in
practice, since the stale state is "recently clean, now edited", and a developer
editing code is not the person asking which build a remote node runs.

### 6.2 A new tag has to retrigger the build

A tag decides the *entire* reported version, and creating or moving one touches
none of the other watched paths — not `HEAD`, not the branch ref, not the index.
So `refs/tags` must be in the rerun-if-changed set or tagging a release changes
nothing about what any already-built binary reports, which is the one case tag
support exists for.

This was a real bug in the first implementation, and it is worth recording how it
surfaced, because nothing else would have caught it: moving a tag onto `HEAD`
made `git describe` return the tag while a rebuilt binary went on reporting the
pre-tag describe string. No test failed, no warning appeared, and a release build
would simply have been mislabelled. It was found only by validating the tagged
path on hardware.

The watch list now lives in `resolve.rs` as `WATCHED_GIT_PATHS`, beside the rules
that consume it, pinned by `the_watch_list_covers_tags_the_commit_and_the_dirty_marker`.
That is a const assertion, and it is worth being clear about what it does and does
not buy: it prevents the historical bug's *cause* (the entry going missing) and
proves nothing about the mechanism. A unit test cannot observe cargo's rerun
decision. The env half of that decision *is* observable by running two nested
builds with different `WAYFINDER_BUILD_VERSION` values, and the git half by
tagging and rebuilding — both were done by hand here (§10) rather than automated,
because a nested `cargo` invocation inside the test suite contends for the same
target-directory lock.

Reviewer note: an earlier draft of this doc claimed the rerun behaviour "cannot be
observed from inside a test" flatly. That is too strong — see above.

### 6.3 Nothing can fail the build — and the first version could

Every `git` failure mode collapses to `None`: no `git` on `PATH`, no repository,
a repository git refuses to read (a foreign owner, normal inside a container),
no matching tag. Tier 3 then reports `unknown`. The script has no `unwrap` on a
git result and no error path.

That was originally written as "verified by construction", and it was **false**,
because the risk was never git — it was the injected string, which was printed
into a `cargo::` directive line unvalidated. Those lines are newline-delimited,
so a value's second line *becomes a directive*. Both halves were reproduced:

```
WAYFINDER_BUILD_VERSION="v1.2
cargo::rustc-cfg=wayfinder_build_dirty"   -> node reports dirty=true, source=Injected
WAYFINDER_BUILD_VERSION="v1.2
cargo::bogus=1"                            -> build aborts: Unknown key: `bogus`
```

The first is worse than the second: a build that reports a modified tree while
carrying a version string with no `-dirty` in it, claiming `Injected` — the tier
documented as exact — and contradicting itself. Realistic sources are mundane: a
CI variable assembled from command output, a YAML block scalar, a `--build-arg`
read from a file, a copy-paste with a trailing line.

`present()` now **refuses** any value containing a control character rather than
stripping it (half a version string is a build identity nobody chose), and
`build.rs` emits a `cargo::warning` naming the variable, so a misassembled
variable says so instead of silently mislabelling the build. Pinned by
`a_value_containing_a_control_character_is_refused`.

### 6.3.1 Two silent-failure modes the injected tier still has

Neither is fixable inside `wayfinder-version`, because both are cases where the
*build environment* knows something the script cannot:

- **An omitted `--build-arg`.** The `Dockerfile`'s `RUN` exports the ARG
  unconditionally, so the script sees `Ok("")` — not "absent" — and `present()`
  deliberately treats blank as absent. Inside the Dockerfile, blank means the
  build-arg was omitted, misspelled, or expanded empty, which is exactly when an
  image gets published under a tag while reporting `unknown`. So the *Dockerfile*
  warns, and `.github/workflows/ci.yml` refuses outright: for a release,
  "unknown" is never an acceptable answer.
- **`docker compose build`** (the documented non-NixOS path) passes no args at
  all, so a locally built image reports `unknown`. The warning above is what an
  operator sees; wiring compose `args:` is deliberately left out, since compose
  has no commit to pass.

### 6.4 The Nix dependency cache must not be invalidated

`nix/default.nix` builds one shared `cargoArtifacts = buildDepsOnly commonArgs`
for every package. A revision-dependent environment variable there would change
its hash on every commit and throw the whole dependency cache away each time.

So the variable is set on the `buildPackage` args only — `mkWayfinderPkg` and
`wayfinder-web` — never on `commonArgs`. Workspace crates compile in
`buildPackage` anyway, so this is both correct and free. Confirmed against the
derivations: the final package carries `WAYFINDER_BUILD_VERSION` and
`wayfinder-workspace-deps` does not.

The container build has a related constraint, and the `Dockerfile` already
carries a comment about the same trade-off for `LEPTOS_OUTPUT_NAME`: the version
is referenced **per-command**, not set stage-wide, which keeps the four `COPY`
layers cached and keeps a per-commit value out of every unrelated layer's cache
key. It does *not* save the dependency compiles — that stage has no separate
deps-only layer, so those sit inside the same `RUN` either way.

## 7. Versioning: what this consumes but does not establish

The tagged branch of §4 is currently unreachable, because the repo has no
release tags. That is deliberate — the decision taken with the ticket's author
was to consume tags and not mint one — but it means the tag path ships
exercised only by unit tests.

Two facts constrain whoever establishes the convention:

- CI's `deploy` job already treats a tagged commit as a release
  (`IMAGE_TAG="$CI_COMMIT_TAG"`), and this change makes the reported build
  identity equal that image tag for a released image.
- The `workflow:` gate is `$CI_COMMIT_REF_PROTECTED == "true"`, so **a tag
  pipeline only runs for a protected tag**. An unprotected `v1.2.3` builds
  nothing.

Recommended follow-up: adopt `v<major>.<minor>.<patch>`, protect `v*`, and tag
`main` once, so the tagged path is exercised for real.

## 8. Cost on the tightest target

The dongle (`bins/wayfinder-nrf52840-dongle`, `FLASH : LENGTH = 884K`) measured
release-to-release against the branch point, both builds with
`--remap-path-prefix` so panic-location strings do not skew the comparison:

| Section | Baseline | With provenance | Δ |
| --- | --- | --- | --- |
| `.text` | 497,264 | 498,288 | +1,024 |
| `.rodata` | 85,936 | 86,144 | +208 |
| `.data` | 4,096 | 4,104 | +8 |
| **flash total** | **587,296** | **588,536** | **+1,240** |

+1,240 bytes, 0.14% of the 884K budget, leaving ~309 KiB headroom. Most of it is
`.text` (the added `info!` call sites and the nested-message encode), not the
strings. All three boards still pass `just stack-budget`.

A first measurement without path remapping showed `.rodata` *shrinking* by 14K,
which is not a credible result: the baseline worktree sat at a much longer
filesystem path, and panic-location strings embed it. Worth remembering before
trusting any future size comparison between two checkouts.

## 9. Decisions taken by the implementing session

- **`BuildInfo` nested message**, not a bare string (§5.1) — chosen with the
  ticket's author so HIL and the dashboard can branch on `dirty`.
- **Consume tags, do not mint one** (§7) — likewise.
- **Const fill instead of a provider method** (§5.2) — the one decision worth a
  reviewer's attention.
- `examples/show.rs` in `wayfinder-version` prints the resolved identity, for
  verifying injection by hand (`WAYFINDER_BUILD_VERSION=… cargo run --example
  show`).
- The HIL assertion is a **staleness check**: it compares the attached board's
  reported build with the host tree's const and fails on a mismatch. Note that
  `just hil` does *not* flash — only `just hil-fresh` does — so this test turns
  "these hardware results are about firmware that is not the code under test"
  from an invisible condition into a red one. That was previously unknowable, and
  is the second thing this change buys beyond answering #59's question.

## 10. Hardware validation

All of it against an attached nRF52840 DK, with the board reflashed for each
case.

| Case | Board reported | HIL |
| --- | --- | --- |
| Untagged, modified tree | `build=35dcaee-dirty` | full suite passed |
| Tagged HEAD, clean tree | `build=v0.0.0-provenance-validation` | full suite passed |
| Board tagged, tree untagged | mismatch | staleness check fails, as designed |

The board's own log ring carried the startup line in each case
(`wayfinder_nrf::node: build version="v0.0.0-provenance-validation"
commit="cd63545" dirty=false`), which is the path that matters for a board with
no probe attached.

The tag used was a throwaway (`v0.0.0-provenance-validation`), created on a
temporary commit and **deleted afterwards** — no tag and no commit from this
validation survives, per §3's non-goal. The third row was produced by deleting
the tag while the board still ran the tagged firmware, and its message is the
intended one:

```
board "alpha" is running v0.0.0-provenance-validation but this tree is cd63545
— reflash it, or stop trusting this run: every other assertion here is about
firmware that is not the code under test
```

The tag-and-distance form (`v0.0.0-provenance-validation-1-g1cb5286`) was checked
on the host rather than on the board, since it exercises the same resolution path
as the row above it.

**This is also how §6.2's bug was found**, and the reason to insist on hardware
validation for a feature whose failure mode is a plausible-looking wrong answer:
every test passed while the binary reported a stale version.

## 10a. What the six review passes changed

Recorded because several findings are the kind that would otherwise be
rediscovered, and two were real defects rather than polish.

**Fixed as defects:**

- **Directive injection through an injected version string** (§6.3). The worst
  finding, and reproduced before fixing.
- **`WAYFINDER_BUILD_COMMIT` was never set by any build path**, so every
  Nix-built node (the cloud CA, the Orin, every spoke) and every container node
  reported `commit: "unknown"` — the field unusable in exactly the deployments
  the feature targets. Three passes flagged it independently; the flake and CI
  both had the value to hand. Now wired.
- **A `cfg!`-value handshake that fails silently.** `dirty` and `source` used to
  cross from `build.rs` to `lib.rs` as `rustc-cfg` values. Probing rustc showed
  `--check-cfg` diagnoses an undeclared cfg *name* but **not** an undeclared
  *value*, so misspelling `"injected"` in either file would have made every
  release build report `Unknown`, with no warning and every test green. All four
  values now cross as `rustc-env` strings through a round-trip-tested
  `source_from_name`.
- **The CI image ships no `git`** (`containers/testenv.Dockerfile` installs
  protobuf-compiler, curl, pkg-config, libdbus, unzip, python3, tshark). A test
  asserting `SOURCE != Unknown` therefore asserted a property of the *machine*
  and would have failed the pipeline. Replaced with self-consistency invariants
  that hold wherever the crate is built. Corollary worth knowing: CI's clone is
  also shallow, so the git tier cannot see tags there — another reason release
  labelling goes through injection.
- **The HIL staleness check was blind in the case it was written for** (§10),
  and **two renderers could show a blank row** for a default-filled `BuildInfo`,
  which is a legal proto3 encoding.

**Simplified on the skeptic's argument:**

- `WAYFINDER_BUILD_DIRTY` and its `parse_bool` are gone. Nothing set the
  variable, and its unrecognised-value fallback was *more* confident than the
  input it discarded (`DIRTY=on` silently became "clean, exact"). Both injectors
  encode dirtiness in the version string already.
- `BuildVersion` is gone; `BUILD` is a `Resolved<'static>`. Two types of the same
  shape drift apart silently — add a field to one and the other under-reports.
  Making it one type also gave `build_info_from` a fixture-able seam, which
  matters because `version` and `commit` are the *same string* in an untagged
  checkout, so the existing assertions would have passed through a transposition.

**Declined, with reasons:**

- **Dropping `BuildSource` to a bool.** No renderer branches on `Git` vs
  `Injected` today, which is a fair hit. It stays because the distinction is
  load-bearing *after* the change above: with `dirty` inferred from the version
  string, an injected identity (an image tag) can never report `dirty=true`, so a
  reader needs `source` to know that `false` there means "not determinable"
  rather than "verified clean". It is now surfaced by `wayfinderctl`, the TUI and
  HIL diagnostics rather than by ctl alone.
- **Consolidating the three renderer helpers.** The wording differs per audience
  on purpose ("modified tree" for the CLI and the bench-facing TUI pane,
  "unreleased build" for the web dashboard's non-technical reader). The shared
  part is three lines; a wording-parameterised helper shared across three crates
  would be more code and one more coupling.
- **`#[non_exhaustive]` on `Resolved`.** Cheap and real in isolation, but it
  blocks external struct-literal construction — including the `build_info_from`
  fixture that is the highest-value test here — to defend against a value no code
  path produces (one producer, no deserialization).
- **Grouping `Inputs` by tier.** One named-field construction site, so
  transposition needs a wrong field *name*; the gain is expressiveness, the cost
  is churn in every test literal.
- **Failing the HIL suite on an empty inventory.** The suite's existing
  convention is a clean skip (the ordinary state of a developer laptop), and this
  test should not be the one that breaks it.
- **Splitting the MR.** The ticket asks for capture, carry *and* surface; a crate
  that resolves a version nothing reports would not be reviewable on its own.

## 11. Observability

The field *is* the observability, and it is on the read path every client
already polls, so nothing further is owed. The one thing deliberately not added:
no alarm is raised for a dirty or unknown build. A bench node is legitimately
dirty most of the time, and an alarm that is always on is noise — CLAUDE.md's
rule that an alarm system must not become the flood it reports applies.

## 12. Key file map for the implementer

- `libs/wayfinder-version/{Cargo.toml,build.rs,src/lib.rs,src/resolve.rs,examples/show.rs}`
- `libs/wayfinder-protos/protos/wayfinder/v1alpha/wayfinder.proto` — `NodeInfo`
  field 7, `BuildInfo`, `BuildSource`
- `libs/wayfinder-protos/src/service.rs` — `build_info()` and the
  `handle_router_read` fill
- `bins/wayfinder-ctl/src/output.rs` — `build_line`
- `bins/wayfinder-tui/src/ui.rs` — `build_identity`, `render_overview`
- `bins/wayfinder-web/src/components/overview.rs` — `build_identity`, Node panel
- `libs/wayfinder-hil/src/diagnostics.rs`, `libs/wayfinder-hil/tests/smoke.rs`
- `flake.nix` (`buildVersion`), `nix/default.nix` (`buildVersionEnv`)
- `containers/Dockerfile` (`ARG` + both `cargo build` invocations),
  `.github/workflows/ci.yml` (`deploy`)
- Startup logs: `bins/wayfinder-tap/src/main.rs`,
  `libs/wayfinder-nrf/src/node.rs`, `bins/wayfinder-stm32f411/src/main.rs`
