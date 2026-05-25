# Wayfinder: Universal Edge Mesh Routing Core

## Executive Summary

**Wayfinder** is an ultra-lightweight, zero-allocation Layer 2 routing engine designed to bring resilient, ad-hoc mesh networking to the absolute edge of computing. Built from the ground up in memory-safe Rust, Wayfinder unifies disparate, fragmented physical communication links into a cohesive, self-healing network fabric. 

Unlike traditional routing solutions tied to specific operating systems or heavy network stacks, Wayfinder operates as an isolated control-plane state machine. It can be deployed universally—from bare-metal microcontrollers with kilobytes of RAM to enterprise Linux gateways—providing high-performance, decentralized routing without infrastructure dependencies.

---

## Core Pillars

Wayfinder is engineered around three foundational architectural principles:

### 1. Absolute Portability
Wayfinder completely decouples routing logic from hardware and operating system dependencies. By utilizing a strict `#![no_std]` execution model and eliminating dynamic heap allocations (`alloc`), the core state machine compiles into a deterministic, tiny binary footprint. It treats physical mediums as abstract streams or packet interfaces, allowing the exact same routing code to run on a raw Cortex-M processor, an RTOS, or a containerized Linux service.

### 2. Extensible Interface Architecture
At the heart of Wayfinder is a pluggable link abstraction layer. Hardware interfaces—whether they are point-to-point serial UARTs, broadcast-capable LoRa transceivers, 802.15.4 radios, or standard Ethernet—are wrapped in a unified interface trait. This allows Wayfinder to seamlessly multiplex and route traffic across entirely different physical layers concurrently, providing a future-proof foundation for custom edge protocols and multi-radio routing.

### 3. Compile-Time and Runtime Safety
Leveraging Rust’s strict ownership and type systems, Wayfinder eliminates common and catastrophic networking software vulnerabilities. 
* **Memory Safety:** Eliminates buffer overflows, dangling pointers, and memory leaks natively without the overhead of a garbage collector.
* **Deterministic Execution:** By relying on fixed-capacity data structures (`heapless`) and stack-allocated workspace scratchpads, Wayfinder guarantees predictable execution times and immune-to-fragmentation memory consumption, which is critical for safety-critical and real-time embedded environments.

---

## Architectural Layout
```
+-----------------------------------------------------------+
|                  Application Data Layer                   |
+-----------------------------+-----------------------------+
                              | (Active Query / Ingress)
                              v
+-----------------------------------------------------------+
|                    Wayfinder Core Engine                  |
|  - Reactive State Machine     - Zero-Copy Packet Parsing  |
|  - Bounded Routing Tables     - Path Quality Metrics (TQ) |
+-----------------------------+-----------------------------+
                              | (Link-Agnostic Frames)
                              v
+-----------------------------------------------------------+
|                  Universal Link Abstraction               |
+--------------+--------------+--------------+--------------+
               |                             |
               v                             v
     +-------------------+         +-------------------+
     |   Radio Link A    |         |   Serial Link B   |
     | (SPI / Broadcast) |         | (UART / Framed)   |
     +-------------------+         +-------------------+
```

Wayfinder shifts the paradigm of edge networking by proving that robust, adaptive mesh routing does not require complex kernel modules or resource-heavy hardware—only smart, safe, and highly optimized software architecture.
