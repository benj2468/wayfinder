//! Node-side membership-certificate renewal: the node asks its authority for a
//! fresh certificate before the one it holds lapses.
//!
//! # Why the node has to initiate
//!
//! A certificate authority in this project cannot push. It answers a `SubmitCsr`
//! and nothing else, so the only way a live node's certificate is refreshed is
//! for that node to submit its *existing* keys again while the certificate it
//! holds is still valid. The authority recognises the holder — same address,
//! same identity key — and re-issues on the spot, skipping the approval queue
//! and keeping the lifetime an operator originally approved this device for.
//!
//! # Why it must happen before `not_after`
//!
//! That holder match is `now_unix <= not_after`. One second past it the node is
//! not a renewing holder any more, it is a stranger: the request is parked for
//! an operator's approval, and until somebody approves it the node is off the
//! mesh. Renewal is therefore driven by
//! [`MembershipCert::due_renewal`](wayfinder::wayfinder_auth::MembershipCert::due_renewal)
//! — the last quarter of the window — and never by expiry, which is already too
//! late.
//!
//! # Why the request carries no certificate
//!
//! The connection is opened with the node's identity seed but an *empty*
//! credential, which is the enrollment tier. That is not an oversight and not a
//! weakening: `SubmitCsr` is declared `access: [Admin, SelfKey, Enrollment]`, so
//! presenting this node's own membership certificate would land the connection
//! on the member tier — one request wide, and `SubmitCsr` is not that request.
//! A renewal that authenticated "properly" would be refused.
//!
//! The provider is still pinned by public key
//! ([`RenewalProviderData::node_key`]), so nothing here is trusted on the
//! strength of an address alone.
//!
//! # Where the provider comes from
//!
//! From the node's own state, never from its configuration file. The authority
//! a node renews against is recorded by the enrollment that certified it
//! (`SetAuth`'s provider block) and replaced by every subsequent one, so a node
//! moved from one provider to another renews against the one it now belongs to
//! — and a node whose credential was installed with no provider named renews
//! nowhere rather than reaching back to an authority it may have left. A
//! `provider:` line in a YAML file could say none of that: it is written once,
//! before the node has enrolled with anybody, and stays true only until the
//! first time an operator re-enrolls the node somewhere else.

use std::time::Duration;

use wayfinder_client::Client;
use wayfinder_client::Identity;
use wayfinder_client::NodeAddr;
use wayfinder_protos::service::RenewalProviderData;
use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcome;

/// How often the driver loop asks whether its certificate needs renewing.
///
/// Fifteen minutes. The question is answered from state already in memory, but
/// it is asked from a path that also runs per frame, so it is paced rather than
/// evaluated continuously. The interval is also this node's retry cadence when a
/// renewal fails, which is what sets the floor. Nothing bounds a certificate's
/// lifetime from below — a provider may issue for minutes — so this is a
/// judgement about the deployments this project has, not a guarantee: at a
/// day-long lifetime the six-hour window holds two dozen attempts, at an hour it
/// holds one, and below that a certificate can step from fresh to expired
/// between two checks without this node ever seeing it renewable. A provider
/// issuing certificates that short has to renew its nodes some other way.
///
/// A settled node pays nothing for it: the check reads state already in memory
/// and opens a connection only inside the window.
///
/// A floor on the spacing between checks, not a ceiling on the latency of one:
/// the check runs at the tail of the driver loop, so it happens no more often
/// than the loop wakes. On a node with no mesh interfaces at all — the
/// certificate-authority posture — the loop's own timer falls back to an hour,
/// and the effective cadence is that.
pub(crate) const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How long one renewal attempt may take before it is abandoned.
///
/// Ninety seconds: a TLS handshake and one request/response against a provider
/// that may be several radio hops or a tunnel away, with room to spare, and far
/// under [`RENEWAL_CHECK_INTERVAL`] so an abandoned attempt is retried on the
/// next check rather than costing a cycle.
///
/// It exists because nothing under it has a deadline of its own — not the TCP
/// connect, not the TLS handshake, not the response read. A provider that
/// completes the handshake and then goes silent (a black-holing firewall is the
/// ordinary way this happens) would park the attempt indefinitely, and since the
/// attempt is what releases the single in-flight slot, the node would stop
/// renewing for the life of the process without saying so.
pub(crate) const RENEWAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(90);

/// How long an attempt may be outstanding before the loop gives up on ever
/// hearing from it and reclaims the slot.
///
/// [`RENEWAL_ATTEMPT_TIMEOUT`] bounds the attempt from the inside, so this only
/// catches what that cannot: a task that panicked before it could report. Set
/// well clear of the timeout so a slow-but-live attempt is never displaced by
/// its own supervisor.
pub(crate) const STUCK_ATTEMPT_BUDGET: Duration = Duration::from_secs(10 * 60);

/// Resolve `provider` — the record the node's last enrollment installed — into
/// the address a connection is opened to.
///
/// Fallible because the record crosses the management API as a string and is
/// re-read from disk on every boot, so the node parses it at the moment it
/// dials rather than trusting a check made when it was written. The install
/// path (`RouterAdapter::set_auth`) refuses an address with no host or no port,
/// which is what stops this from being the first place an operator hears about
/// a typo.
pub(crate) fn provider_addr(provider: &RenewalProviderData) -> anyhow::Result<NodeAddr> {
    provider.target.address.parse().map_err(|e| {
        anyhow::anyhow!(
            "the recorded renewal provider address '{}' is unusable: {e}",
            provider.target.address
        )
    })
}

/// The credential a completed renewal produced, in the encodings `SetAuth`
/// accepts.
#[derive(Clone, Debug)]
pub(crate) struct Renewed {
    /// The re-issued membership certificate, raw `MembershipCert` bytes.
    pub(crate) cert: Vec<u8>,
    /// The trust anchor it chains to, in `TrustAnchor::to_bytes` form.
    ///
    /// Carried even though this node already holds an anchor: a certificate and
    /// the anchor that verifies it are one credential, and installing the
    /// certificate alone would be trusting that the authority's answer chains to
    /// what this node happens to have. `SetAuth` verifies the pair together.
    pub(crate) trust_anchor: Vec<u8>,
    /// The provider this certificate came from — the record to re-install
    /// alongside it.
    ///
    /// Carried through the attempt rather than re-read when it lands, because
    /// the record and the certificate are one thing: what the node stores must
    /// be the authority that issued what the node is holding. Re-reading would
    /// pair this certificate with whatever the record says by then, which for
    /// the one case where they differ — an operator re-enrolling this node while
    /// the attempt was outstanding — is precisely the wrong pairing.
    pub(crate) provider: RenewalProviderData,
}

/// What this node's own certificate currently is, as far as renewal is
/// concerned.
///
/// Three states rather than the two `due_renewal` answers, because "not due" is
/// two opposite situations — a certificate with most of its life ahead of it and
/// one that has already lapsed — and collapsing them is how a node ends up
/// silently off the mesh with a cleared alarm. Deriving the verdict here, as a
/// value, is what lets the loop's handling of each be read side by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertCondition {
    /// Valid, with more than the last quarter of its window remaining. Nothing
    /// to report and nothing to do.
    Fresh,
    /// Valid, inside the last quarter: renewable now, and the only state in
    /// which an authority still re-issues on the spot.
    DueRenewal,
    /// Past `not_after`. Peers no longer accept this node's OGMs, and the
    /// authority no longer recognises it as a renewing holder — a fresh
    /// enrollment now, which needs an operator. Renewal cannot rescue it.
    Expired,
}

/// Classify `cert` as of `now_unix`.
pub(crate) fn cert_condition(
    cert: &wayfinder::wayfinder_auth::MembershipCert,
    now_unix: u64,
) -> CertCondition {
    if cert.expired(now_unix) {
        CertCondition::Expired
    } else if cert.due_renewal(now_unix) {
        CertCondition::DueRenewal
    } else {
        CertCondition::Fresh
    }
}

/// Paces the renewal check and keeps at most one attempt outstanding.
///
/// Split out from the driver loop as plain owned state with an explicit `now`,
/// so the pacing rules are testable without a socket, a clock, or a provider —
/// the same split [`AlarmBoard`](wayfinder_alarm::AlarmBoard) makes for the same
/// reason.
#[derive(Debug, Default)]
pub(crate) struct RenewalGate {
    /// Loop instant of the last evaluation, or `None` before the first.
    checked: Option<Duration>,
    /// Loop instant the outstanding attempt claimed the slot, or `None` when no
    /// attempt is running.
    ///
    /// The instant rather than a bare flag, so an attempt that never reports
    /// back can be told from one that is merely slow. Without that distinction
    /// the slot is unrecoverable: nothing but the attempt itself ever releases
    /// it, so a task that dies without sending stops this node renewing for the
    /// life of the process.
    in_flight_since: Option<Duration>,
}

impl RenewalGate {
    /// Whether the certificate should be evaluated on this turn of the loop.
    ///
    /// True on the first call and then at most once per
    /// [`RENEWAL_CHECK_INTERVAL`]. Records the evaluation as having happened, so
    /// two calls in one turn do not both pass.
    pub(crate) fn should_check(&mut self, now: Duration) -> bool {
        if let Some(last) = self.checked
            && now.saturating_sub(last) < RENEWAL_CHECK_INTERVAL
        {
            return false;
        }
        self.checked = Some(now);
        true
    }

    /// Claim the single in-flight slot, returning whether it was free.
    ///
    /// One attempt at a time is the whole of the backpressure here, and it is
    /// enough: a provider that is down leaves this node retrying on the check
    /// interval rather than opening a connection per loop iteration, and a
    /// provider that is merely slow is not asked the same question twice
    /// concurrently.
    pub(crate) fn begin(&mut self, now: Duration) -> bool {
        if self.in_flight_since.is_some() {
            return false;
        }
        self.in_flight_since = Some(now);
        true
    }

    /// How long an outstanding attempt has held the slot past
    /// [`STUCK_ATTEMPT_BUDGET`], or `None` when the slot is free or its holder
    /// is still inside the budget.
    ///
    /// The caller's cue to report the attempt as lost and release the slot —
    /// which is a decision worth making out loud, hence a query here and a
    /// [`finish`](Self::finish) there, rather than a silent reclaim inside
    /// [`begin`](Self::begin).
    pub(crate) fn stuck_for(&self, now: Duration) -> Option<Duration> {
        let held = now.saturating_sub(self.in_flight_since?);
        (held >= STUCK_ATTEMPT_BUDGET).then_some(held)
    }

    /// Release the in-flight slot once an attempt has finished, succeeded or
    /// not.
    pub(crate) fn finish(&mut self) {
        self.in_flight_since = None;
    }
}

/// Ask `provider` — the authority this node's certificate was issued by — to
/// re-issue one for the identity it already holds.
///
/// `seed` is the node's own identity seed — used only to terminate the TLS
/// handshake, never sent — and `mac`/`ed_pubkey`/`x_pubkey` are the identity
/// being re-certified. They are passed in rather than derived here so that the
/// caller reads them from the router under its lock, once, and this function
/// holds no router state across the network round trip it performs.
pub(crate) async fn request_renewal(
    provider: &RenewalProviderData,
    seed: [u8; 32],
    mac: [u8; 6],
    ed_pubkey: [u8; 32],
    x_pubkey: [u8; 32],
) -> anyhow::Result<Renewed> {
    // No certificate: see the module header. Presenting this node's membership
    // cert would earn the member tier, which `SubmitCsr` is not on.
    let identity = Identity {
        seed,
        cert: Vec::new(),
    };
    let address = provider_addr(provider)?;
    let mut client = Client::connect_tls(&address, &provider.target.node_key, &identity).await?;
    let response = client
        .submit_csr(
            &mac,
            &ed_pubkey,
            &x_pubkey,
            provider.enrollment_token.expose(),
        )
        .await?;
    match response.outcome {
        Some(CsrOutcome::Issued(issued)) => Ok(Renewed {
            cert: issued.cert,
            trust_anchor: issued.trust_anchor,
            provider: provider.clone(),
        }),
        // A rejection is terminal for *this* certificate — the caller retries on
        // the next interval, which is right when the cause is a token an
        // operator has since fixed, and harmless when it is not: the request is
        // refused before it touches the provider's held-CSR store.
        Some(CsrOutcome::Rejected(rejected)) => {
            anyhow::bail!("the authority refused the renewal: {}", rejected.reason)
        }
        // Pending means the provider did *not* recognise this node as a live
        // holder — the certificate lapsed before the renewal landed, or the node
        // has been revoked — and has parked the request for an operator. Worth
        // its own message rather than a generic failure, because the remedy is
        // a person approving a queue entry, not anything this node can retry
        // its way out of.
        Some(CsrOutcome::Pending(_)) => anyhow::bail!(
            "the authority parked the renewal for operator approval: this node is \
             no longer recognised as a live holder, so it must be approved with \
             `wayfinderctl provider requests approve` before it can route again"
        ),
        // No outcome at all is a different thing entirely: the far end answered
        // with something this build cannot read — a newer provider, or a bug.
        // Told apart from the parked case rather than folded into it, because
        // that message names a remedy (approve the queued request) that would
        // queue nothing here and send an operator looking for a row that does
        // not exist.
        None => anyhow::bail!(
            "the authority answered the renewal with no outcome this build understands; \
             it may be running a newer management protocol than this node"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_protos::service::RenewalTargetData;
    use wayfinder_protos::service::SharedSecret;

    /// The check is paced, not continuous: the first turn evaluates, and the
    /// next evaluation is a whole interval away.  This runs from a path that
    /// also runs per frame, so an unpaced check would ask the same question
    /// thousands of times a second on a busy node.
    #[test]
    fn the_check_runs_once_per_interval() {
        let mut gate = RenewalGate::default();

        assert!(
            gate.should_check(Duration::ZERO),
            "the first turn evaluates"
        );
        assert!(
            !gate.should_check(Duration::ZERO),
            "a second call on the same turn does not"
        );
        assert!(
            !gate.should_check(RENEWAL_CHECK_INTERVAL - Duration::from_secs(1)),
            "still inside the interval"
        );
        assert!(
            gate.should_check(RENEWAL_CHECK_INTERVAL),
            "the interval has elapsed"
        );
        assert!(
            !gate.should_check(RENEWAL_CHECK_INTERVAL + Duration::from_secs(1)),
            "and the next one is measured from that evaluation, not from zero"
        );
    }

    /// Only one attempt is outstanding at a time.  Without this a provider that
    /// accepts connections but never answers would collect one dangling
    /// connection per check for as long as it stayed that way.
    #[test]
    fn only_one_attempt_is_outstanding_at_a_time() {
        let mut gate = RenewalGate::default();

        assert!(gate.begin(Duration::ZERO), "the slot starts free");
        assert!(
            !gate.begin(Duration::ZERO),
            "and is claimed until the attempt finishes"
        );

        gate.finish();
        assert!(gate.begin(Duration::ZERO), "finishing releases it");
    }

    /// A *failed* attempt releases the slot too — the caller finishes on both
    /// arms.  If it did not, one unreachable provider would wedge renewal for
    /// the life of the process, and the node would lapse without ever retrying.
    #[test]
    fn a_finished_attempt_releases_the_slot_however_it_ended() {
        let mut gate = RenewalGate::default();
        assert!(gate.begin(Duration::ZERO));
        // However the attempt ended, the driver calls `finish`.
        gate.finish();
        gate.finish();
        assert!(gate.begin(Duration::ZERO), "a redundant finish is harmless");
    }

    /// The three conditions are distinguished, and in particular a lapsed
    /// certificate is not folded in with a healthy one.  Both answer "no" to
    /// "should I renew?", and treating them alike is how a node that has fallen
    /// off the mesh reports itself as fine.
    #[test]
    fn a_certificate_is_classified_fresh_due_or_expired() {
        use wayfinder::wayfinder_auth::CERT_VERSION;
        use wayfinder::wayfinder_auth::MembershipCert;
        use zerocopy::byteorder::network_endian::U32;
        use zerocopy::byteorder::network_endian::U64;

        // Built directly rather than issued: nothing here inspects the
        // signature, and the host-only `Authority` is not in this crate's
        // dependency graph. Valid 1000..1400, so the last quarter opens at 1300.
        let cert = MembershipCert {
            version: CERT_VERSION,
            flags: 0,
            mesh_id: U32::new(0xABCD),
            node_mac: [0, 0, 0, 0, 0, 1],
            ed_pubkey: [0u8; 32],
            x_pubkey: [0u8; 32],
            not_before: U64::new(1000),
            not_after: U64::new(1400),
            signature: [0u8; 64],
        };

        assert_eq!(cert_condition(&cert, 1000), CertCondition::Fresh);
        assert_eq!(cert_condition(&cert, 1299), CertCondition::Fresh);
        assert_eq!(cert_condition(&cert, 1300), CertCondition::DueRenewal);
        assert_eq!(cert_condition(&cert, 1400), CertCondition::DueRenewal);
        assert_eq!(
            cert_condition(&cert, 1401),
            CertCondition::Expired,
            "past not_after this is not 'nothing to do', it is the worst state"
        );
    }

    /// The recorded address resolves to something dialable, and a record that
    /// cannot name a host and port is refused rather than dialled.
    ///
    /// Parsed at the moment of use, not once at startup: this record arrives
    /// over the management API and is re-read from disk on every boot, so the
    /// node has to be able to say what is wrong with one it has been handed.
    #[test]
    fn the_recorded_provider_address_resolves_at_the_moment_it_is_dialled() {
        let provider = RenewalProviderData {
            target: RenewalTargetData {
                address: "ca.example:7700".into(),
                node_key: [1u8; 32],
            },
            enrollment_token: SharedSecret::new("s3cret"),
        };
        let addr = provider_addr(&provider).expect("a host:port record is dialable");
        assert_eq!(addr.host(), "ca.example");
        assert_eq!(addr.port(), 7700);

        let broken = RenewalProviderData {
            target: RenewalTargetData {
                address: "not a host:port".into(),
                ..provider.target
            },
            ..provider
        };
        assert!(
            provider_addr(&broken).is_err(),
            "an unusable record is reported, not dialled"
        );
    }

    /// Pacing and the in-flight slot are independent: an attempt still running
    /// when the next interval comes around does not suppress the *check*, it is
    /// suppressed by [`RenewalGate::begin`].  Keeping them separate is what lets
    /// the alarm be raised on a certificate whose renewal is stuck.
    #[test]
    fn pacing_and_the_in_flight_slot_are_independent() {
        let mut gate = RenewalGate::default();
        assert!(gate.should_check(Duration::ZERO));
        assert!(gate.begin(Duration::ZERO));

        assert!(
            gate.should_check(RENEWAL_CHECK_INTERVAL),
            "the certificate is still evaluated while an attempt is outstanding"
        );
        assert!(
            !gate.begin(RENEWAL_CHECK_INTERVAL),
            "but no second attempt starts"
        );
    }

    /// An attempt that never reports back is eventually given up on, and the
    /// slot it held is reclaimable.
    ///
    /// This is the failure the in-flight slot creates rather than prevents:
    /// nothing but the attempt itself releases the slot, so a task that dies
    /// without sending — a panic, or any path the attempt's own timeout cannot
    /// reach — would stop this node renewing for the life of the process, with
    /// every later check taking the "already running" early return in silence.
    #[test]
    fn an_attempt_that_never_returns_is_given_up_on() {
        let mut gate = RenewalGate::default();
        assert!(gate.begin(Duration::ZERO));

        assert_eq!(
            gate.stuck_for(STUCK_ATTEMPT_BUDGET - Duration::from_secs(1)),
            None,
            "a slow attempt inside its budget is not displaced by its supervisor"
        );
        assert_eq!(
            gate.stuck_for(STUCK_ATTEMPT_BUDGET),
            Some(STUCK_ATTEMPT_BUDGET),
            "past the budget it is reported, with how long it has been held"
        );

        gate.finish();
        assert_eq!(
            gate.stuck_for(STUCK_ATTEMPT_BUDGET * 2),
            None,
            "a free slot is never stuck"
        );
        assert!(
            gate.begin(STUCK_ATTEMPT_BUDGET * 2),
            "and is claimable again"
        );
    }

    /// The attempt's own budget sits well under the check interval, so a
    /// timed-out attempt is retried on the next check rather than costing a
    /// cycle — and the supervisor's budget sits above the attempt's, so a
    /// slow-but-live attempt is never abandoned by it.
    ///
    /// Asserted rather than left to the comments because all three constants are
    /// tuned independently and the ordering between them is what makes the
    /// retry cadence the module documents true.
    #[test]
    fn the_attempt_budgets_are_ordered_against_the_check_interval() {
        assert!(RENEWAL_ATTEMPT_TIMEOUT < RENEWAL_CHECK_INTERVAL);
        assert!(RENEWAL_ATTEMPT_TIMEOUT < STUCK_ATTEMPT_BUDGET);
    }
}
