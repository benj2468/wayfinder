# Wayfinder — Universal Edge Mesh Routing Core

**Wayfinder** is an ultra-lightweight, zero-allocation mesh routing engine that
brings resilient, ad-hoc networking to the absolute edge of computing. It's an
implementation of [BATMAN-adv]-style routing written from the ground up in
memory-safe Rust, unifying disparate physical links — LoRa, IEEE 802.15.4,
Ethernet — into one self-healing network fabric.

The routing core is `#![no_std]` and heap-free, so the **exact same code** runs
on a bare-metal microcontroller with kilobytes of RAM and on a Linux gateway.
Host concerns (the event loop, sockets, the management API, dashboards) live in
separate crates layered cleanly on top.

[BATMAN-adv]: https://www.open-mesh.org/projects/batman-adv/wiki

---

## Core Pillars

### 1. Absolute Portability
A strict `#![no_std]`, no-`alloc` execution model compiles the core state
machine into a tiny, deterministic binary. Physical mediums are abstract frame
carriers, so identical routing logic runs on a raw Cortex-M, an RTOS, or a
containerized Linux service.

### 2. Extensible Interface Architecture
A pluggable link abstraction (`LinkT`) wraps every hardware interface — serial
UARTs, broadcast LoRa transceivers, 802.15.4 radios, Ethernet — behind one
trait. Wayfinder multiplexes and routes traffic across entirely different
physical layers **concurrently**.

### 3. Compile-Time & Runtime Safety
Rust's ownership and type systems eliminate buffer overflows, dangling
pointers, and leaks natively — no garbage collector. Fixed-capacity
(`heapless`) data structures give **predictable execution times** and
fragmentation-immune memory use, critical for real-time embedded environments.

### 4. Observability as a First-Class Citizen
A mesh node sits *underneath* the apps that run on it, so Wayfinder surfaces its
internal state — link quality, topology size, route stability, throughput,
capacity pressure — through a management API. Apps and operators can *see the
network they're standing on* and adapt to it.

### 5. Optional Mesh Segregation
Meshes can be gated by a per-mesh trust anchor: a node joins only with a
membership certificate binding `Ed25519 key ↔ MAC ↔ mesh`. OGMs are signed
(authenticity, not confidentiality — payloads are never encrypted), so
outsiders and foreign nodes can't inject topology.

---

## Architecture

```
+-----------------------------------------------------------+
|                  Application / Host (TAP)                 |
+-----------------------------+-----------------------------+
                              | (link-agnostic frames)
                              v
+-----------------------------------------------------------+
|                    Wayfinder Core Engine                  |
|  - BATMAN routing state machine   - zero-copy parsing     |
|  - bounded routing tables         - path quality (TQ)     |
|  - throughput / occupancy metrics - optional OGM auth     |
+-----------------------------+-----------------------------+
                              | (LinkT interfaces)
        +---------------------+---------------------+
        v                     v                     v
  +-----------+         +-----------+         +-----------+
  |    LoRa   |         | 802.15.4  |         | UDP / TAP |
  | (RYLR998) |         |  radios   |         |  (host)   |
  +-----------+         +-----------+         +-----------+
```

---

## Workspace Layout

### Core routing (`no_std`)
| Crate | What it does |
| --- | --- |
| `libs/interfaces` | Shared abstractions: `Mac` node address, `LinkFrame`, `MeshRoutingEngine`, `RoutingAction`, `LinkMetrics` |
| `libs/batman` | BATMAN-adv engine — originator table, OGM topology discovery, unicast/broadcast/multicast forwarding, Trickle-paced (RFC 6206) OGM emission |
| `libs/wayfinder` | `CentralRouter` orchestration — the `LinkT` interface trait, protocol demux, multicast egress planning, throughput/occupancy metrics, and opt-in OGM authentication |

### Radio drivers (`no_std`)
| Crate | What it does |
| --- | --- |
| `libs/rylr998` | REYAX RYLR998/RYLR498 LoRa module driver (async AT commands) as a `LinkT` |
| `libs/ieee802154` | Hardware-agnostic IEEE 802.15.4 frame encode/decode |
| `libs/at86rf233` | SPI driver for the Atmel/Microchip AT86RF233 802.15.4 transceiver |
| `libs/nrf-ieee802154` | `LinkT` adapter for the nRF52840's built-in 802.15.4 radio (`embassy-nrf`) |

### Identity & management API
| Crate | What it does |
| --- | --- |
| `libs/wayfinder-auth` | Membership certs, Ed25519 signing/verification, X25519 pairwise keys, and the host-side certificate authority |
| `libs/wayfinder-protos` | `prost`/protobuf management API (`wayfinder.v1alpha`) — node info, routing, link quality, throughput, metrics, security, cert enrollment |
| `libs/wayfinder-server` | The management-API server: a `no_std` router adapter plus tokio TCP/Unix/UDP listeners and the provider-mode CA |
| `libs/wayfinder-client` | Reusable client for the management API (TCP length-delimited or Unix datagram) |

### Host driver, tooling & tests
| Crate | What it does |
| --- | --- |
| `libs/wayfinder-driver` | The `std`/tokio event loop — transport-agnostic `FrameIo` carriers, plus IPv4 IGMP multicast snooping |
| `libs/wayfinder-test` | `Switch` simulator + `TestRouter` for multi-node integration tests (no hardware) |
| `libs/wayfinder-shark` | Wireshark/`tshark` Lua dissector for on-air BATMAN frames, with pytest tests |
| `bins/wayfinder-tap` | The runnable node — bridges a kernel TAP onto the mesh over UDP and serves the management API |
| `bins/wayfinder-tui` | `ratatui` terminal dashboard: routing, link quality, OGM schedule, throughput, and security tabs |
| `bins/wayfinder-ctl` | `wayfinderctl` CLI — query a live node or mint/enroll node certificates offline |

---

## Quick Start

```bash
# Build everything
cargo build

# Run the full test suite
cargo test --workspace

# Run a mesh node from a YAML config (TAP bridge + UDP links + management API)
cargo run -p wayfinder-tap -- --config node.yaml

# Watch a running node in the terminal dashboard
cargo run -p wayfinder-tui -- <node-addr>

# Query a node or mint certs from the command line
cargo run -p wayfinder-ctl -- routes
```

---

## Development

This project is developed **test-first** — write the failing test, then make
it pass. Every public API carries documentation (enforced for protobuf via
`buf lint`), and all diagnostics go through the [`tracing`] facade.

```bash
nix fmt                                # format the whole tree (treefmt)
cargo clippy --workspace               # lint
cargo test --workspace                 # test
cd libs/wayfinder-protos && buf lint   # proto docs + style
```

Contributions ship through GitLab merge requests with
[Conventional Commits](https://www.conventionalcommits.org/) titles
(`type(scope): summary`). See [`CLAUDE.md`](./CLAUDE.md) for the full
architecture, conventions, and contributor guide.

[`tracing`]: https://docs.rs/tracing
