//! Helper for building a mesh link over a REYAX RYLR998/RYLR498 LoRa module
//! attached to a local serial port.
//!
//! The module (or its USB-serial adapter) can drop off the bus at any time —
//! unplugged, power-cycled, swapped for a blank unit. [`ReconnectingRylr998Link`]
//! detects that on the next `Io` error, reopens the port, and re-issues the
//! `AT+ADDRESS`/`AT+NETWORKID`/`AT+PARAMETER` setup sequence, so the link
//! recovers without a `wayfinder-tap` restart.

use std::time::Duration;
use std::time::Instant;

use embedded_io_adapters::tokio_1::FromTokio;
use tokio_serial::SerialPortBuilderExt;
use tokio_serial::SerialStream;

use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::DynLinkT;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

/// Map a `spreading_factor` config value onto its [`SpreadingFactory`]
/// variant, rejecting anything outside the module's supported 5..=11 range.
fn spreading_factor_from(value: u8) -> anyhow::Result<SpreadingFactory> {
    Ok(match value {
        5 => SpreadingFactory::Sf5,
        6 => SpreadingFactory::Sf6,
        7 => SpreadingFactory::Sf7,
        8 => SpreadingFactory::Sf8,
        9 => SpreadingFactory::Sf9,
        10 => SpreadingFactory::Sf10,
        11 => SpreadingFactory::Sf11,
        other => anyhow::bail!("invalid spreading_factor {other}: must be 5..=11"),
    })
}

/// Map a `bandwidth_khz` config value onto its [`Bandwidth`] variant,
/// rejecting anything the module doesn't support.
fn bandwidth_from(khz: u16) -> anyhow::Result<Bandwidth> {
    Ok(match khz {
        125 => Bandwidth::Khz125,
        250 => Bandwidth::Khz250,
        500 => Bandwidth::Khz500,
        other => anyhow::bail!("invalid bandwidth_khz {other}: must be 125, 250, or 500"),
    })
}

/// Map a `coding_rate_denominator` config value onto its [`CodingRate`]
/// variant, rejecting anything the module doesn't support.
fn coding_rate_from(denominator: u8) -> anyhow::Result<CodingRate> {
    Ok(match denominator {
        5 => CodingRate::Cr45,
        6 => CodingRate::Cr46,
        7 => CodingRate::Cr47,
        8 => CodingRate::Cr48,
        other => anyhow::bail!("invalid coding_rate_denominator {other}: must be 5, 6, 7, or 8"),
    })
}

/// Exponential backoff for reconnect attempts, paced by wall-clock instants
/// rather than a blocking sleep.
///
/// [`ReconnectingRylr998Link::ensure_connected`] is called from `send`/`recv`,
/// which the driver's per-iteration `select!` reconstructs fresh on every
/// call (see `wayfinder-driver::driver::run_once`) — an `await` that blocked
/// for the backoff window would just get cancelled and restarted from
/// scratch before it ever finished. Tracking "when is the next attempt due"
/// as a plain instant instead lets a caller poll `ready`/`record_failure`
/// cheaply on every call without ever blocking, while still never retrying
/// the real (expensive) connect faster than the backoff schedule intends.
struct Backoff {
    /// Fixed baseline delay: what `current` starts at and returns to on
    /// [`Self::reset`]. Never changes after construction.
    initial: Duration,
    /// Delay doubling saturates at, however many failures accumulate.
    max: Duration,
    /// Delay the *next* [`Self::record_failure`] will schedule.
    current: Duration,
    /// Instant before which `ready` reports `false`. `None` before any
    /// failure has been recorded, or after [`Self::reset`].
    next_attempt_at: Option<Instant>,
}

impl Backoff {
    /// Delay after the first failure, for [`Self::new`].
    const DEFAULT_INITIAL: Duration = Duration::from_secs(1);
    /// Delay doubling saturates here, for [`Self::new`].
    const DEFAULT_MAX: Duration = Duration::from_secs(30);

    /// A fresh backoff using this link's production bounds (1s..=30s): ready
    /// immediately, starting at [`Self::DEFAULT_INITIAL`].
    fn new() -> Self {
        Self::with_bounds(Self::DEFAULT_INITIAL, Self::DEFAULT_MAX)
    }

    /// A fresh backoff with explicit bounds — used by tests to keep a
    /// reconnect scenario fast without waiting out real production delays.
    /// `initial` is clamped to `max`, so `current <= max` always holds even
    /// if a caller passes bounds the wrong way round.
    fn with_bounds(initial: Duration, max: Duration) -> Self {
        let initial = initial.min(max);
        Self {
            initial,
            max,
            current: initial,
            next_attempt_at: None,
        }
    }

    /// Whether `now` has reached the delay scheduled by the last
    /// [`Self::record_failure`] (or there was none).
    fn ready(&self, now: Instant) -> bool {
        self.next_attempt_at.is_none_or(|at| now >= at)
    }

    /// Record a failed attempt at `now`, returning the delay before the next
    /// one is allowed and doubling (capped at this backoff's max) the delay
    /// for the failure after that.
    fn record_failure(&mut self, now: Instant) -> Duration {
        let delay = self.current;
        self.next_attempt_at = Some(now + delay);
        self.current = (self.current * 2).min(self.max);
        delay
    }

    /// Reset to the initial delay after a successful connection.
    fn reset(&mut self) {
        self.current = self.initial;
        self.next_attempt_at = None;
    }
}

/// How a [`ReconnectingRylr998Link`] obtains the raw byte stream it hands to
/// a fresh [`RylrClient`].
///
/// Production opens a real serial port ([`SerialConnector`]); tests
/// substitute the in-process `rylr998-sim` simulator (see
/// `libs/rylr998-sim`), so a connection failure and recovery can be driven
/// deterministically — killing and replacing the simulated module — without
/// real hardware.
trait Rylr998Connector: Send {
    /// The byte stream a [`RylrClient`] built from [`Self::connect`] will
    /// read/write.
    type Stream: embedded_io_async::Read + embedded_io_async::Write + Send;

    /// Open a fresh connection to the module.
    async fn connect(&mut self) -> anyhow::Result<Self::Stream>;
}

/// Opens a real RYLR998/RYLR498 module over a local serial port.
struct SerialConnector {
    /// Serial device path (e.g. `/dev/ttyUSB0`).
    device: String,
    /// UART baud rate.
    baud_rate: u32,
}

impl Rylr998Connector for SerialConnector {
    type Stream = FromTokio<SerialStream>;

    async fn connect(&mut self) -> anyhow::Result<Self::Stream> {
        let stream = tokio_serial::new(&self.device, self.baud_rate).open_native_async()?;
        Ok(FromTokio::new(stream))
    }
}

/// A [`LinkT`] over a REYAX RYLR998/RYLR498 module, transparently
/// reconnecting (via `C`, see [`Rylr998Connector`]) and re-applying this
/// link's configuration if the connection ever drops.
///
/// The module's own `AT+ADDRESS`/`AT+NETWORKID`/`AT+PARAMETER` settings
/// persist across a bare power cycle of the radio (they're written to its
/// NVM), but the *host-side* connection does not survive the module (or its
/// USB-serial adapter) dropping off the bus — a new [`RylrClient`] has to be
/// built and configured from scratch. `send`/`recv` detect that via an `Io`
/// error and, on the next call, reconnect through [`Self::ensure_connected`],
/// gated by [`Backoff`] so a persistently absent device doesn't get hammered.
struct ReconnectingRylr998Link<C: Rylr998Connector> {
    /// How to (re)open the underlying byte stream.
    connector: C,
    /// A human-readable label for this link, used only in log lines (e.g.
    /// the serial device path in production, or a test's own label).
    name: String,
    /// This node's `AT+ADDRESS` value, reapplied on every reconnect.
    address: u16,
    /// `AT+NETWORKID` group, reapplied on every reconnect.
    network_id: u8,
    /// LoRa spreading factor, reapplied on every reconnect.
    spreading_factor: SpreadingFactory,
    /// RF channel bandwidth, reapplied on every reconnect.
    bandwidth: Bandwidth,
    /// LoRa coding rate, reapplied on every reconnect.
    coding_rate: CodingRate,
    /// Programming preamble length, reapplied on every reconnect.
    preamble: u8,
    /// The live client, or `None` while disconnected/reconnecting.
    inner: Option<RylrClient<C::Stream>>,
    /// Set by `send`/`recv` on an `Io` error; consumed (dropping `inner`) by
    /// the next [`Self::ensure_connected`]. A separate flag rather than
    /// clearing `inner` directly at the error site, because `recv`'s
    /// borrow-checked signature ties its returned [`Received`] to the same
    /// borrow of `self` that would be needed to clear `inner` inline.
    broken: bool,
    /// Reconnect pacing.
    backoff: Backoff,
}

impl<C: Rylr998Connector> ReconnectingRylr998Link<C> {
    /// Open a fresh connection via the connector and push this link's
    /// configuration to the module.
    async fn connect(&mut self) -> anyhow::Result<RylrClient<C::Stream>> {
        let stream = self.connector.connect().await?;
        let mut client = RylrClient::new(stream)?;
        client.set_address(self.address).await?;
        client.set_network_id(self.network_id).await?;
        client
            .set_parameters(
                self.spreading_factor,
                self.bandwidth,
                self.coding_rate,
                self.preamble,
            )
            .await?;
        Ok(client)
    }

    /// Make sure a live, configured client is available, reconnecting if the
    /// previous one broke, and return it.
    ///
    /// Never blocks on the backoff window itself (see [`Backoff`]'s docs):
    /// while a reconnect is still pending, this returns `Err` immediately
    /// rather than sleeping, so a caller polling it every driver iteration
    /// never stalls the whole event loop out on a long backoff.
    async fn ensure_connected(&mut self) -> Result<&mut RylrClient<C::Stream>, LinkError> {
        if self.broken {
            self.inner = None;
            self.broken = false;
        }
        if self.inner.is_none() {
            let now = Instant::now();
            if !self.backoff.ready(now) {
                return Err(LinkError::Io);
            }
            match self.connect().await {
                Ok(client) => {
                    self.inner = Some(client);
                    self.backoff.reset();
                    tracing::info!(name = %self.name, "rylr998 link (re)connected");
                }
                Err(e) => {
                    let delay = self.backoff.record_failure(now);
                    tracing::warn!(
                        error = ?e,
                        name = %self.name,
                        delay_ms = delay.as_millis(),
                        "rylr998 link connect failed; will retry"
                    );
                    return Err(LinkError::Io);
                }
            }
        }
        // `self.inner` was just confirmed `Some` above (either it already
        // was, or the connect arm just set it) — this can't actually be
        // `None`, but the compiler can't see that across the branches above,
        // so it still needs a fallible unwrap here.
        self.inner.as_mut().ok_or(LinkError::Io)
    }
}

impl<C: Rylr998Connector> LinkT for ReconnectingRylr998Link<C> {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let client = self.ensure_connected().await?;
        let result = client.send(origin, data).await;
        if matches!(&result, Err(LinkError::Io)) {
            tracing::warn!(name = %self.name, "rylr998 link send failed; will reconnect");
            self.broken = true;
        }
        result
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Unlike `send`, this can't bind `ensure_connected`'s returned
        // reference: `recv`'s own return type ties its `Received` borrow to
        // `'a` (all of `*self`), so holding that reference across the match
        // below would block the `self.broken = true`/`self.name` accesses in
        // the `Err` arm. Call it for effect and re-borrow `self.inner`
        // directly afterward instead — the same direct field access
        // `self.broken`'s doc comment already explains the need for.
        self.ensure_connected().await?;
        let Some(client) = self.inner.as_mut() else {
            return Err(LinkError::Io);
        };
        match client.recv().await {
            Ok(received) => Ok(received),
            Err(e) => {
                if matches!(e, LinkError::Io) {
                    tracing::warn!(name = %self.name, "rylr998 link recv failed; will reconnect");
                    self.broken = true;
                }
                Err(e)
            }
        }
    }
}

/// Parameters for [`build_rylr998_link`], mirroring
/// [`LinkTransport::Rylr998`](wayfinder::config::LinkTransport::Rylr998)'s
/// fields. A dedicated struct rather than eight positional arguments — three
/// of which (`spreading_factor`, `coding_rate_denominator`, `preamble`) are
/// same-shaped `u8`s a caller could transpose without a type error.
pub struct Rylr998LinkParams {
    /// Serial device path the module is attached to (e.g. `/dev/ttyUSB0`).
    pub device: String,
    /// UART baud rate.
    pub baud_rate: u32,
    /// This node's `AT+ADDRESS` value.
    pub address: u16,
    /// `AT+NETWORKID` group.
    pub network_id: u8,
    /// LoRa spreading factor: 5..=11.
    pub spreading_factor: u8,
    /// RF channel bandwidth in kHz: 125, 250, or 500.
    pub bandwidth_khz: u16,
    /// LoRa coding rate, as the `4/x` denominator: 5, 6, 7, or 8.
    pub coding_rate_denominator: u8,
    /// Programming preamble length.
    pub preamble: u8,
}

/// Build a mesh link over a REYAX RYLR998/RYLR498 module, type-erased as a
/// [`LinkT`](wayfinder::link::LinkT).
///
/// Fails fast — before any port is opened — on an invalid parameter, and
/// fails on the initial connection exactly as before (a bad `device` path at
/// startup is still a startup error). Once connected, the returned link
/// transparently reconnects and reconfigures itself if the connection drops
/// later; see [`ReconnectingRylr998Link`].
pub async fn build_rylr998_link(
    params: Rylr998LinkParams,
) -> anyhow::Result<Box<DynLinkT<'static>>> {
    let spreading_factor = spreading_factor_from(params.spreading_factor)?;
    let bandwidth = bandwidth_from(params.bandwidth_khz)?;
    let coding_rate = coding_rate_from(params.coding_rate_denominator)?;

    let mut link = ReconnectingRylr998Link {
        connector: SerialConnector {
            device: params.device.clone(),
            baud_rate: params.baud_rate,
        },
        name: params.device,
        address: params.address,
        network_id: params.network_id,
        spreading_factor,
        bandwidth,
        coding_rate,
        preamble: params.preamble,
        inner: None,
        broken: false,
        backoff: Backoff::new(),
    };
    let client = link.connect().await?;
    link.inner = Some(client);

    Ok(DynLinkT::new_box(link))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::RwLock;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use rylr998_sim::NodeState;
    use rylr998_sim::RylrSimulator;
    use tokio::io::DuplexStream;
    use tokio::task::JoinHandle;

    use super::*;

    /// Every boundary of the module's supported spreading-factor range is
    /// accepted; anything outside it is rejected with a message naming the
    /// bad value.
    #[test]
    fn spreading_factor_from_accepts_supported_range_and_rejects_others() {
        for v in 5..=11u8 {
            assert!(spreading_factor_from(v).is_ok(), "sf {v} should be valid");
        }
        let err = spreading_factor_from(12).unwrap_err();
        assert!(err.to_string().contains("12"));
    }

    /// Only the three bandwidths the module supports are accepted.
    #[test]
    fn bandwidth_from_accepts_supported_values_and_rejects_others() {
        assert!(bandwidth_from(125).is_ok());
        assert!(bandwidth_from(250).is_ok());
        assert!(bandwidth_from(500).is_ok());
        let err = bandwidth_from(333).unwrap_err();
        assert!(err.to_string().contains("333"));
    }

    /// Only the four coding-rate denominators the module supports are
    /// accepted.
    #[test]
    fn coding_rate_from_accepts_supported_values_and_rejects_others() {
        for v in 5..=8u8 {
            assert!(
                coding_rate_from(v).is_ok(),
                "denominator {v} should be valid"
            );
        }
        let err = coding_rate_from(9).unwrap_err();
        assert!(err.to_string().contains('9'));
    }

    /// A valid set of parameters but a serial device that doesn't exist must
    /// surface as a clean error, not a panic.
    #[tokio::test]
    async fn build_fails_cleanly_when_serial_device_does_not_exist() {
        let result = build_rylr998_link(Rylr998LinkParams {
            device: "/dev/definitely-not-a-real-rylr998-device".into(),
            baud_rate: 115_200,
            address: 1,
            network_id: 18,
            spreading_factor: 7,
            bandwidth_khz: 125,
            coding_rate_denominator: 5,
            preamble: 15,
        })
        .await;
        assert!(result.is_err());
    }

    /// An invalid parameter is rejected before any serial port is opened —
    /// proven by using an obviously bad device path that would otherwise
    /// fail with a different (I/O) error.
    #[tokio::test]
    async fn build_rejects_invalid_spreading_factor_before_opening_serial_port() {
        let err = match build_rylr998_link(Rylr998LinkParams {
            device: "/dev/definitely-not-a-real-rylr998-device".into(),
            baud_rate: 115_200,
            address: 1,
            network_id: 18,
            spreading_factor: 12,
            bandwidth_khz: 125,
            coding_rate_denominator: 5,
            preamble: 15,
        })
        .await
        {
            Ok(_) => panic!("invalid spreading_factor must be rejected before opening the port"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("spreading_factor"));
    }

    /// A fresh `Backoff` lets the first attempt through immediately.
    #[test]
    fn backoff_is_ready_before_any_failure() {
        let backoff = Backoff::new();
        assert!(backoff.ready(Instant::now()));
    }

    /// Each recorded failure doubles the delay (starting at 1s), and
    /// `ready` reports `false` until that delay has elapsed from the instant
    /// the failure was recorded.
    #[test]
    fn backoff_doubles_and_gates_readiness_until_the_delay_elapses() {
        let mut backoff = Backoff::new();
        let t0 = Instant::now();

        let d1 = backoff.record_failure(t0);
        assert_eq!(d1, Duration::from_secs(1));
        assert!(!backoff.ready(t0));
        assert!(!backoff.ready(t0 + d1 - Duration::from_millis(1)));
        assert!(backoff.ready(t0 + d1));

        let d2 = backoff.record_failure(t0 + d1);
        assert_eq!(d2, Duration::from_secs(2));

        let d3 = backoff.record_failure(t0 + d1 + d2);
        assert_eq!(d3, Duration::from_secs(4));
    }

    /// Doubling saturates at a fixed cap rather than growing unbounded.
    #[test]
    fn backoff_caps_at_the_maximum_delay() {
        let mut backoff = Backoff::new();
        let mut now = Instant::now();
        let mut delay = Duration::ZERO;
        for _ in 0..10 {
            delay = backoff.record_failure(now);
            now += delay;
        }
        assert_eq!(delay, Duration::from_secs(30));
    }

    /// `reset` (called after a successful reconnect) drops back to the
    /// initial delay and clears any pending gate, so the very next failure
    /// starts the backoff sequence over.
    #[test]
    fn backoff_reset_returns_to_the_initial_delay() {
        let mut backoff = Backoff::new();
        let t0 = Instant::now();
        backoff.record_failure(t0);
        backoff.record_failure(t0 + Duration::from_secs(1));

        backoff.reset();
        assert!(backoff.ready(t0));
        assert_eq!(backoff.record_failure(t0), Duration::from_secs(1));
    }

    /// `reset` returns to *this instance's* configured initial delay, not a
    /// global default — otherwise a test-tuned (fast) backoff would jump back
    /// to the multi-second production delay after its first success.
    #[test]
    fn backoff_reset_uses_this_instances_own_initial_delay() {
        let mut backoff = Backoff::with_bounds(Duration::from_millis(5), Duration::from_millis(20));
        let t0 = Instant::now();
        backoff.record_failure(t0);
        backoff.record_failure(t0 + Duration::from_millis(5));

        backoff.reset();
        assert_eq!(backoff.record_failure(t0), Duration::from_millis(5));
    }

    /// One spun-up simulated module: its live configuration state (for a
    /// test to inspect) and the task driving it (so a test can kill this
    /// "session" with `.abort()`).
    type SimSession = (Arc<RwLock<NodeState>>, JoinHandle<()>);

    /// A [`Rylr998Connector`] backed by the in-process `rylr998-sim`
    /// simulator: each `connect()` spins up a fresh simulated module (a new
    /// `tokio::io::duplex` pair plus a [`RylrSimulator`] task), so a test can
    /// kill one [`SimSession`] and observe the next `connect()` configuring a
    /// brand new one — standing in for a real module dropping off the bus
    /// and coming back.
    #[derive(Default)]
    struct SimConnector {
        /// One entry per successful `connect()`, in order.
        sessions: Arc<Mutex<Vec<SimSession>>>,
        /// While `> 0`, `connect()` fails and decrements this instead of
        /// succeeding.
        fail_next: Arc<AtomicUsize>,
        /// Total number of `connect()` calls, successful or not.
        attempts: Arc<AtomicUsize>,
        /// When `true`, the next simulated module `connect()` spins up
        /// rejects every AT command (`+ERR=-1`) — standing in for a module
        /// that answers on the bus but won't accept reconfiguration.
        /// Cleared after one use.
        reject_next_session: Arc<AtomicBool>,
    }

    impl Rylr998Connector for SimConnector {
        type Stream = FromTokio<DuplexStream>;

        async fn connect(&mut self) -> anyhow::Result<Self::Stream> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail_next.load(Ordering::SeqCst) > 0 {
                self.fail_next.fetch_sub(1, Ordering::SeqCst);
                anyhow::bail!("simulated connect failure");
            }
            let (client_stream, sim_stream) = tokio::io::duplex(4096);
            let (mut sim, _handle) = RylrSimulator::new(sim_stream);
            if self.reject_next_session.swap(false, Ordering::SeqCst) {
                sim.force_error = Some(-1);
            }
            let state = sim.state.clone();
            let task = tokio::spawn(sim.run());
            self.sessions.lock().unwrap().push((state, task));
            Ok(FromTokio::new(client_stream))
        }
    }

    /// Asserts a [`SimSession`]'s observed config matches this link's fixed
    /// test configuration — address 42, network id 7, SF9/250kHz/CR46,
    /// preamble 8 — covering every field `AT+PARAMETER` carries, not just
    /// `AT+ADDRESS`/`AT+NETWORKID`.
    fn assert_full_test_configuration_applied(session: &SimSession) {
        let state = session.0.read().unwrap();
        assert_eq!(state.address, 42);
        assert_eq!(state.network_id, 7);
        assert_eq!(state.spreading_factor, SpreadingFactory::Sf9 as u8);
        assert_eq!(state.bandwidth, Bandwidth::Khz250 as u8);
        assert_eq!(state.coding_rate, CodingRate::Cr46 as u8);
        assert_eq!(state.preamble, 8);
    }

    /// After the live connection breaks, the next `recv` surfaces the I/O
    /// error, and the call after that transparently reconnects — spinning up
    /// a fresh simulated module and re-applying this link's *full*
    /// configuration to it (not just the address, and not just at startup).
    #[tokio::test]
    async fn reconnects_and_reapplies_configuration_after_the_connection_breaks() {
        let connector = SimConnector::default();
        let sessions = connector.sessions.clone();

        let mut link = ReconnectingRylr998Link {
            connector,
            name: "test".into(),
            address: 42,
            network_id: 7,
            spreading_factor: SpreadingFactory::Sf9,
            bandwidth: Bandwidth::Khz250,
            coding_rate: CodingRate::Cr46,
            preamble: 8,
            inner: None,
            broken: false,
            backoff: Backoff::with_bounds(Duration::from_millis(5), Duration::from_millis(20)),
        };

        link.ensure_connected().await.unwrap();
        {
            let sessions = sessions.lock().unwrap();
            assert_eq!(sessions.len(), 1);
            assert_full_test_configuration_applied(&sessions[0]);
        }

        // Kill the live session out from under the client — simulating the
        // module (or its USB-serial adapter) dropping off the bus.
        sessions.lock().unwrap()[0].1.abort();
        tokio::task::yield_now().await;

        let result = tokio::time::timeout(Duration::from_secs(1), link.recv())
            .await
            .expect("recv should observe the broken connection promptly, not hang");
        let err = match result {
            Ok(_) => panic!("a killed connection must surface as an error"),
            Err(e) => e,
        };
        assert!(matches!(err, LinkError::Io));
        assert!(link.broken);

        // Wait out the (test-tuned, tiny) backoff window, then reconnect.
        tokio::time::sleep(Duration::from_millis(10)).await;
        link.ensure_connected().await.unwrap();

        let sessions = sessions.lock().unwrap();
        assert_eq!(sessions.len(), 2, "should have spun up a second session");
        assert_full_test_configuration_applied(&sessions[1]);
    }

    /// The realistic failure shape: the first reconnect attempt still fails
    /// (the device isn't back yet), and only the one after that succeeds —
    /// not just "breaks once, immediately reconnects" or "always fails".
    #[tokio::test]
    async fn reconnects_after_an_intermediate_failed_attempt() {
        let connector = SimConnector::default();
        let sessions = connector.sessions.clone();
        let fail_next = connector.fail_next.clone();
        let attempts = connector.attempts.clone();

        let mut link = ReconnectingRylr998Link {
            connector,
            name: "test".into(),
            address: 42,
            network_id: 7,
            spreading_factor: SpreadingFactory::Sf9,
            bandwidth: Bandwidth::Khz250,
            coding_rate: CodingRate::Cr46,
            preamble: 8,
            inner: None,
            broken: false,
            backoff: Backoff::with_bounds(Duration::from_millis(5), Duration::from_millis(20)),
        };

        link.ensure_connected().await.unwrap();
        sessions.lock().unwrap()[0].1.abort();
        tokio::task::yield_now().await;
        assert!(link.recv().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        // The device is still absent for the first retry.
        fail_next.store(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(link.ensure_connected().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            sessions.lock().unwrap().len(),
            1,
            "the failed retry must not have spun up a new session"
        );

        // It comes back for the second retry.
        tokio::time::sleep(Duration::from_millis(10)).await;
        link.ensure_connected().await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        let sessions = sessions.lock().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_full_test_configuration_applied(&sessions[1]);
    }

    /// `send`'s own Io-detection/reconnect path — exercised directly, since
    /// the other reconnect tests only drive `recv`/`ensure_connected`.
    #[tokio::test]
    async fn send_reconnects_after_the_connection_breaks() {
        use wayfinder::interfaces::frame::LinkFrameData;
        use wayfinder::interfaces::frame::Mac;

        let connector = SimConnector::default();
        let sessions = connector.sessions.clone();

        let mut link = ReconnectingRylr998Link {
            connector,
            name: "test".into(),
            address: 42,
            network_id: 7,
            spreading_factor: SpreadingFactory::Sf9,
            bandwidth: Bandwidth::Khz250,
            coding_rate: CodingRate::Cr46,
            preamble: 8,
            inner: None,
            broken: false,
            backoff: Backoff::with_bounds(Duration::from_millis(5), Duration::from_millis(20)),
        };

        link.ensure_connected().await.unwrap();
        sessions.lock().unwrap()[0].1.abort();
        tokio::task::yield_now().await;

        let data = LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: 0x4305,
            payload: &[1, 2, 3],
        };
        // The first send after the break observes the dead connection.
        let result = tokio::time::timeout(Duration::from_secs(1), link.send(Mac::BROADCAST, &data))
            .await
            .expect("send should observe the broken connection promptly, not hang");
        assert!(result.is_err());
        assert!(link.broken);

        // The next one, after the backoff window, reconnects and succeeds.
        tokio::time::sleep(Duration::from_millis(10)).await;
        link.send(Mac::BROADCAST, &data)
            .await
            .expect("send should succeed once reconnected");

        let sessions = sessions.lock().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_full_test_configuration_applied(&sessions[1]);
    }

    /// If the module rejects the reconfiguration commands on a reconnect
    /// attempt (e.g. a real module wedged in a bad state, or a replacement
    /// unit that hasn't finished booting), that attempt must fail cleanly
    /// rather than leaving `inner` set to a half-configured client.
    #[tokio::test]
    async fn reconnect_fails_cleanly_when_the_module_rejects_reconfiguration() {
        let connector = SimConnector::default();
        let reject_next_session = connector.reject_next_session.clone();

        let mut link = ReconnectingRylr998Link {
            connector,
            name: "test".into(),
            address: 42,
            network_id: 7,
            spreading_factor: SpreadingFactory::Sf9,
            bandwidth: Bandwidth::Khz250,
            coding_rate: CodingRate::Cr46,
            preamble: 8,
            inner: None,
            broken: false,
            backoff: Backoff::with_bounds(Duration::from_millis(5), Duration::from_millis(20)),
        };

        link.ensure_connected().await.unwrap();

        // Force a reconnect, and arrange for the replacement module to
        // reject every AT command it's sent.
        link.broken = true;
        reject_next_session.store(true, Ordering::SeqCst);

        let result = link.ensure_connected().await;
        assert!(
            result.is_err(),
            "a module rejecting AT+ADDRESS/etc. must fail the reconnect, not silently succeed"
        );
        assert!(
            link.inner.is_none(),
            "a failed reconnect must not leave a half-configured client installed"
        );
    }

    /// A connector that keeps failing is retried only as often as [`Backoff`]
    /// allows, proving `ensure_connected` doesn't hammer it on every poll —
    /// the behavior the driver's per-iteration `select!` relies on (see
    /// [`Backoff`]'s docs).
    #[tokio::test]
    async fn ensure_connected_gates_retries_by_backoff_and_does_not_hammer_the_connector() {
        let connector = SimConnector::default();
        let attempts = connector.attempts.clone();
        connector.fail_next.store(usize::MAX, Ordering::SeqCst);

        let mut link = ReconnectingRylr998Link {
            connector,
            name: "test".into(),
            address: 1,
            network_id: 18,
            spreading_factor: SpreadingFactory::Sf7,
            bandwidth: Bandwidth::Khz125,
            coding_rate: CodingRate::Cr45,
            preamble: 15,
            inner: None,
            broken: false,
            backoff: Backoff::with_bounds(Duration::from_millis(30), Duration::from_millis(100)),
        };

        assert!(link.ensure_connected().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        // Immediately retrying, before the backoff window elapses, must not
        // touch the connector again.
        assert!(link.ensure_connected().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(link.ensure_connected().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
