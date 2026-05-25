# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a research project implementing BATMAN-adv (Better Approach To Mobile Adhoc Networking) mesh routing for embedded systems and LoRa radio communication. The project is structured as a Cargo workspace with multiple libraries focusing on different aspects of mesh networking.

## Building and Testing

### Build Commands
```bash
# Build the entire workspace
cargo build

# Build a specific package
cargo build -p batman
cargo build -p runner
cargo build -p rylr998
cargo build -p interfaces

# Build with release optimizations
cargo build --release
```

### Testing Commands
```bash
# Run all tests in the workspace
cargo test

# Run tests for a specific package
cargo test -p runner
cargo test -p batman

# Run a specific test by name
cargo test test_poll_and_route

# Run tests with output visible
cargo test -- --nocapture
```

### Running Binaries
```bash
# Run the tun binary
cargo run --bin tun
```

## Architecture

### Workspace Structure

The project is organized into four main libraries:

**libs/interfaces** - Core abstractions and traits for the mesh networking system:
- `MeshRoutingEngine` trait: Defines routing protocol behavior (handle_rx, produce_periodic_broadcast)
- `EmbeddedMeshLink` trait: Abstracts physical layer communication
- `MeshIdentifier` trait: Type constraint for node addresses (implemented for u8 by default)
- `LinkFrame`: Zero-copy link-layer frame structure with src/dst/protocol/payload
- `RoutingAction` enum: Returned by routing engines (Consumed, ForwardTo, DeliverLocal)

**libs/batman** - BATMAN-adv routing protocol implementation:
- `BatmanEngine<MAX_ORIGINATORS, Ident>`: Core routing engine with originator table
- `BatmanOgmPacket`: Originator Messages (OGM) for topology discovery
- `BatmanUnicastPacket`: Unicast data packets with TTL and destination
- Implements `MeshRoutingEngine` trait
- Uses heapless data structures for embedded compatibility
- Protocol constants: `ETH_P_BATMAN` (0x4305), `BATADV_IV_OGM` (0x01), `BATADV_UNICAST` (0x03)

**libs/runner** - Central router orchestration:
- `CentralRouter<Ident, N>`: Manages multiple physical interfaces and routing engine
- `DEFAULT_BATMAN_ETHER_TYPE`: 0x4305
- `poll_and_route()`: Main event loop - polls all interfaces, processes received frames, handles periodic OGM broadcasts
- `dispatch_from_local()`: Sends application data to mesh destination
- Protocol demultiplexing based on LinkFrame protocol field

**libs/rylr998** - REYAX RYLR998/RYLR498 LoRa module driver:
- `RylrClient<S>`: Async AT command interface for LoRa modules
- Configuration methods: set_mode, set_rf_frequency, set_parameters (spreading factor, bandwidth, coding rate)
- `send_data()`: Transmit up to 240 bytes to target address
- `listen_for_packet()`: Async receive with RSSI/SNR metrics
- Supports network IDs, encryption passwords, RF output power configuration

### Key Design Patterns

**Zero-copy parsing**: Uses `zerocopy` crate for efficient packet handling without allocations. All wire format structs derive `FromBytes`, `IntoBytes`, `Immutable`, `KnownLayout`.

**Async I/O**: Built on `tokio` for async operations. Physical links implement `AsyncRead + AsyncWrite`.

**Trait-based abstraction**: Routing engines and physical links are abstracted via traits, enabling protocol/hardware flexibility.

**No-std compatibility**: BATMAN engine uses `heapless::Vec` for fixed-capacity collections suitable for embedded systems.

**Test infrastructure**: The runner tests include a `Mesh` simulator with `tokio::io::duplex` for testing multi-node scenarios without hardware.

## Important Implementation Details

### BATMAN Routing Logic

The BATMAN engine maintains an originator table tracking:
- `neighbor_ident`: The destination node
- `best_next_hop`: Immediate neighbor to forward packets to
- `max_tq`: Transmission Quality metric (0-255)
- `paths`: Up to 4 alternate paths via different neighbors

OGM processing (libs/batman/src/engine.rs:31-134):
1. Drops own OGMs (loop prevention)
2. Creates or updates originator record
3. Computes path quality (TQ -= 10 per hop)
4. Selects best path based on highest TQ
5. Forwards OGM with decremented TTL and updated prev_sender

Unicast forwarding (libs/batman/src/engine.rs:137-179):
1. Checks if packet is for local node (DeliverLocal)
2. Validates TTL > 1
3. Looks up next hop in originator table
4. Returns ForwardTo action with immediate neighbor address

### Link Layer Frame Format

All frames use `LinkFrame<Ident>` structure (libs/interfaces/src/frame.rs):
- `src: Ident` - Source identifier (added by link layer)
- `dst: Ident` - Destination identifier (or BROADCAST)
- `protocol: u16` - EtherType-style protocol identifier
- `payload: [u8]` - Variable-length payload

### Protocol Multiplexing

The CentralRouter demuxes by protocol field (libs/runner/src/lib.rs:56-89):
- `0x4305` (DEFAULT_BATMAN_ETHER_TYPE): Routes to BATMAN engine
- `0x88B5`: Reserved for experimental protocols
- Other values are dropped

## Common Development Patterns

### Adding a new routing protocol

1. Implement `MeshRoutingEngine<Ident>` trait in a new library
2. Add protocol constant (EtherType) to identify your protocol
3. Update `CentralRouter::poll_and_route()` match statement to handle your protocol
4. Create wire format packet structs with zerocopy derives

### Implementing a physical radio driver

1. Implement `EmbeddedMeshLink<Ident>` trait
2. `transmit()`: Serialize LinkFrameData and send via hardware
3. `receive()`: Read from hardware, parse into LinkFrame
4. Handle broadcast addresses appropriately for your medium

### Testing with simulated mesh

Use `IdentifiableLink` wrapper with `tokio::io::duplex` for unit tests:
```rust
let (a, b) = tokio::io::duplex(3000);
let link = Box::new(IdentifiableLink { identifier: 0, link: a });
let router = CentralRouter::new([link], 0);
```

## Edition Note

Some packages use `edition = "2024"` which is not yet stable as of the knowledge cutoff. When modifying Cargo.toml files, be aware of edition compatibility.
