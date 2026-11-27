# Agent roadmap

The backlog the agent team draws tasks from, and the place Ben steers it. An
agent takes **the first unchecked item in its lane that is not already covered
by an open PR**, breaks it down if it is bigger than one PR, and ticks it off
in the PR that finishes it. Reorder or edit this file to redirect the team; it
is read from `origin/main` on every run, so a change takes effect once merged.

Direction (chosen 2026-11-26): software-only work first, focused on
**adversarial modelling in the sim** and **AI on the Orin**. They are one plan:
attacks produce exactly the scenarios where classical TQ is wrong, which is
what `ml/README.md` says the learned next-hop model is missing.

## Where the sim stands

`sim/scenarios/red_team.py` (~47 protocol attacks, HELD / BY DESIGN / GAP
verdicts, HTML report), `captured_device.py`, `jammer_map.py`; primitives
`Simulation.inject`, `flood`, `wiretap`, `add_jammer`, `forge.*`.

Gaps in the attacker model:

- Attackers are outsiders injecting bytes; there is no **insider that
  misbehaves at forwarding**.
- Wiretaps attach to a named link, not a position: eavesdropping is not
  range- or terrain-aware.
- The jammer is wideband only (`interference.py` notes reactive and
  protocol-aware jammers are unmodelled).
- Attacks are isolated unit tests on `PerfectWire`, not mission-impact
  measurements.

## Phase 1 — sim (lane: ml-engineer)

The ml-engineer owns *all* simulation: adversarial work, characterisation and
modelling alike. The items below are the current adversarial priority. When
none of them is actionable (all in flight, or blocked), the next work is
characterisation or modelling that the sim lacks, for example:

- convergence and reroute time versus topology size, density and mobility;
- OGM overhead versus Trickle parameters;
- validating the channel and terrain models against real-radio numbers.

Propose such work as a new roadmap item in the PR description, because this
file is Ben's to edit.

- [ ] **1.1 Insider misbehaviour** on captured nodes: blackhole, grayhole
  (drop %), **selective forwarding** (relay OGMs, drop data — TQ stays
  perfect, so BATMAN routes *into* the attacker), delay, **wormhole** (two
  colluding radios tunnel authenticated OGMs). Implement in Python by filtering
  a captured node's egress by BATMAN packet type (`forge.PACKET_*`); no
  `wayfinder-py` change expected. Add a `selective_forwarding.py` scenario on an
  existing field topology measuring delivery ratio and TQ over time; add
  wormhole/blackhole cases to the red-team battery. Expected verdicts: GAP —
  that is the point.
- [ ] **1.2 `Adversary` actor**: position, mobility, radio, power/duty budget,
  a policy hook on each frame/tick. Subsumes wiretap/inject/jammer into one
  physical model.
- [ ] **1.3 Reactive and partial-band jammers** plus a **frequency-hopping
  channel model**; metric = attacker energy per denied packet, hopping vs not.
- [ ] **1.4 Scenario randomisation** from a seed (node count, mobility, channel
  parameters, attacker placement). Also closes `ml/README.md` gap #1.
- [ ] **1.5 Sweeps** (`sweep.py`): delivery vs number compromised,
  time-to-reroute, worst-case jammer placement. Charts for wayfndr.dev/sim.

## Phase 2 — models (lane: ml-engineer)

- [ ] **2.1 Design doc: a data-plane signal** for the router (e.g. per-neighbour
  end-to-end delivery). No model can catch a selective forwarder from OGM-only
  features, and this touches shared crates, so it is a design doc first —
  the agent writes the doc, Ben decides.
- [ ] **2.2 Retrain next-hop** on the attack scenarios (after 2.1 lands).
- [ ] **2.3 Misbehaving/jammed-neighbour detector** feeding the existing alarms.

## Phase 3 — Orin (not yet assigned; needs Ben)

`nix/machines/orin-nano`, CUDA 8.7 already configured.

- `ort` + TensorRT EP in `wayfinder-tap` behind the `argmax(last_tq)` seam.
- **Shadow mode first**: score, log disagreement with BATMAN as a metric, do
  not act. Enable only once sim + HIL back it.
- Honest framing (from `ml/README.md`): the 11-input model runs in
  microseconds on CPU. The GPU earns its place in training sweeps and heavier
  on-node detection, not this forward pass.

## Frequency hopping (decided: software MAC, not a new radio)

- The WL55 (SX126x-based) has no LoRa FHSS; LR-FHSS is TX-only. Do slow
  per-packet/slotted hopping in software via retuning.
- FCC 15.247 (902–928 MHz): <250 kHz channels → ≥50 hops, ≤0.4 s per 20 s,
  up to 1 W; 250–500 kHz → ≥25 hops, ≤0.4 s per 10 s, 0.25 W if <50 channels.
  500 kHz LoRa may already qualify as digital modulation (1 W without hopping).
- It does not beat a full-band jammer. The hard part is the mesh: broadcast
  OGMs assume a shared channel, so hopping needs time sync (clock-trust work),
  rendezvous/rejoin, and reworked flooding.
- Order: model it in the sim first (1.3) → design doc → WL55 implementation
  validated by HIL (Ben).

## Security (lane: security-engineer)

`type::security` and bug issues in the lane come first (`rules.md`): #105,
persisting the revocation list, outranks everything below.

- [ ] **S.1 Design 27 §10 gate spike, part 1: the AEAD.**
  ChaCha20-Poly1305 with the 8-byte-ICV construction, pinned to RFC 8439
  vectors. Its flash cost and cycles/byte in `wayfinder-bench` on
  `thumbv7em-none-eabihf` and `thumbv7em-none-eabi` (the WL55 image). The
  bench is out of lane: keep it to the measurement.
- [ ] **S.2 Gate spike, part 2: fragment counts with the overhead.** Extend
  `extended_format_collapses_realistic_ogm_fragment_counts`
  (`libs/blue/src/frame.rs`), and add the equivalents for `ieee802154` and
  `lora-link`, covering every message §10 lists at SecTAG versions 0 and 1.
  Then apply §10's decision rule, and write the verdict into design 27. Ben
  decides whether the gate passes.
- [ ] **S.3 `wayfinder-linksec`** (only after Ben passes the gate): SecTAG,
  AEAD, replay window, the exchange messages and their state machine, with
  §11's tests and fuzz targets. Creating the crate needs Ben's OK on the
  workspace edit.
- [ ] **S.4 Red-team battery upkeep:** a case for each new attack primitive
  the ml-engineer builds (insider forwarding, wormhole, …). Keep every
  verdict backed by a test.

## Later roles (not yet running)

| Role | Lane | Notes |
|---|---|---|
| Firmware engineer | `bins/wayfinder-*`, radio drivers | Board portability (shared driver crates, a `just new-board` scaffold, bring-up doc), fitting small parts (design 28), per-board benches; radio-timing changes need Ben's HIL run |
