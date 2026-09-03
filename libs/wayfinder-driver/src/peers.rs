//! [`AuthView`]: the slice of authentication state a key-addressed carrier
//! needs, published by the driver from the router's verified certificate store
//! and observable through a generation counter.
//!
//! Exists for one carrier's benefit — `IrohLink`, whose transport address for
//! a peer *is* that peer's identity key — but deliberately holds no iroh types
//! and sits behind no feature gate, so `driver.rs` can populate it without
//! knowing which carrier (if any) will read it.
//!
//! # Why this is not on `LinkT`
//!
//! `LinkT` is `no_std` and implemented by the nRF/STM32 boards and every radio
//! driver. LoRa, BLE and 802.15.4 address by MAC on a shared broadcast medium:
//! there is no key to learn and no connection to tear down, so auth state would
//! be dead weight on every one of them. This is an *optional handle a carrier
//! opts into*, in keeping with the root `CLAUDE.md`'s rule to gate the
//! implementation and not the seam.
//!
//! # The two things it carries
//!
//! **Peer keys** (`Mac → Ed25519 public key`). A learned link table records
//! *which endpoint relayed a frame*, which on a hub topology is the hub for
//! every spoke behind it — deliverable, but it routes every spoke-to-spoke
//! packet through the hub. A certificate binds a MAC to the key of the node
//! that actually owns it, so resolving here lets two spokes address each other
//! directly. That is the fix
//! `docs/design/implemented/08-internet-links-headscale-vpn.md` §9 describes as
//! needing "the node's own UDP endpoint carried in an OGM TVLV" — and which
//! needs no new wire format, because the address *is* the key and design 01
//! already distributes certificates mesh-wide.
//!
//! **Stale keys**, the ones a carrier must stop talking to. Two sources, and a
//! carrier wants them together because its response to both is identical —
//! close the connection:
//!
//! * **Revoked.** Without this, revocation stops at the routing layer: the
//!   engine refuses a revoked node's frames, but a connection-oriented carrier
//!   keeps the connection open, keeps it in the broadcast fan-out set, and
//!   keeps reading from it. Routing is denied; the socket is not.
//! * **Superseded.** A node that re-keyed has a *new* certificate for the same
//!   MAC. The old key must not keep a live connection that would shadow it.
//!   This is what makes a rotated certificate-authority key reachable again
//!   without editing every spoke's config — see the rotation note below.
//!
//! # What rotation this does and does not fix
//!
//! **Live rotation works.** A node that is connected when a peer re-keys hears
//! the peer's new OGM, fails the fingerprint match, fetches the new certificate
//! over the mesh (design 01), verifies it against the trust anchor, and
//! republishes. The old key goes stale, its connection closes, and the next
//! frame dials the new one. Nothing is configured and nothing is hand-edited.
//!
//! **Cold rotation does not.** The certificate store is in-memory, so a node
//! that was *offline* when the authority re-keyed restarts with an empty view
//! and only its configured `bootstrap_peers` to dial — which now name a key
//! nobody answers on. Recovering needs the new key delivered out of band
//! (`SetAuth` over the management API, or a config change). That is a real
//! limitation and not one this type can close: learning the key requires a
//! connection, and the connection requires the key.
//!
//! # Why a snapshot rather than a borrow
//!
//! The certificate store lives inside `CentralRouter`, which the driver loop
//! owns exclusively; a carrier cannot borrow from it while the loop is running.
//! The driver republishes a snapshot on its own cadence instead, so a carrier
//! reads an uncontended lock on the data path and watches a `u64` to know when
//! anything changed.
//!
//! An empty view is the normal state for a mesh with authentication off, and a
//! carrier must treat it as "no information", never as "no such peer" — it
//! falls back to whatever it learned from received frames.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;

use interfaces::frame::Mac;
use tokio::sync::watch;

/// How many stale keys are retained. Bounds the memory a long-lived node
/// spends remembering keys it must refuse.
///
/// Generous against both sources: the revocation table the router itself keeps
/// is far smaller, and a supersession only happens when a peer re-keys. A node
/// that overflows this has re-keyed its whole mesh several times over without
/// restarting, and the cost of forgetting the oldest entry is bounded — the
/// key is not resurrected, it merely stops being *proactively* closed, and any
/// frame from it still fails the router's own authentication.
const MAX_STALE_KEYS: usize = 256;

/// The published state, replaced wholesale on each publish.
#[derive(Default, Debug)]
struct AuthState {
    /// This node's own identity seed, or `None` while it has none.
    ///
    /// A key-addressed carrier cannot bind an endpoint without it — the
    /// endpoint *is* this key — and must not bind one to a seed the node is
    /// about to replace. A node that has not enrolled yet has no identity worth
    /// announcing, so a carrier stays dormant until this appears, and rebinds
    /// if `SetAuth` later rotates it. Both transitions are live: `SetAuth`
    /// replaces the router's auth and this slot without a restart.
    ///
    /// A secret, deliberately, and the reason this type is never serialised,
    /// logged or sent anywhere. It goes no further than the process that
    /// already holds it — the same seed the management TLS server presents.
    identity: Option<[u8; 32]>,
    /// Where the authority is reachable on the mesh, as recorded at enrolment:
    /// `<64 hex chars>[@ip:port]`.
    ///
    /// The one peer a key-addressed carrier can dial before it has heard
    /// anything, and the reason such a carrier needs no bootstrap peer in its
    /// config: the node is told who the authority is over the management API,
    /// at the only moment it could be, and that travels here rather than into
    /// a file a node might not have.
    ca_endpoint: Option<String>,
    /// `Mac → Ed25519 public key`, from certificates verified against the mesh
    /// trust anchor. Only live, non-revoked entries.
    peers: HashMap<Mac, [u8; 32]>,
    /// Keys a carrier must not hold a connection to: revoked or superseded.
    stale: HashSet<[u8; 32]>,
    /// The last key seen for each MAC, including MACs no longer in `peers`.
    ///
    /// Needed because a revocation names a **MAC, not a key**, and the router
    /// evicts the neighbor's cached certificate when it ingests one — so by the
    /// time a revocation is visible, the key it condemns is already gone from
    /// the store. This remembers it. Pruned to `peers ∪ revoked` on every
    /// publish, so it cannot grow with every node ever seen.
    known: HashMap<Mac, [u8; 32]>,
}

/// A shared, cheaply-cloned view of the authentication state a key-addressed
/// carrier needs.
///
/// Cloning shares the underlying state: the driver holds one handle to publish
/// through and each interested carrier holds another to read.
#[derive(Clone, Debug)]
pub struct AuthView {
    state: Arc<RwLock<AuthState>>,
    /// Bumped whenever a publish actually changed something. A carrier compares
    /// it against what it last acted on, so the common case — a publish that
    /// changed nothing — costs one `u64` load and no lock.
    generation: watch::Sender<u64>,
}

impl Default for AuthView {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthView {
    /// An empty view — the state of a mesh with authentication disabled, and of
    /// any node before its first certificate is verified.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AuthState::default())),
            generation: watch::Sender::new(0),
        }
    }

    /// Replace the view's contents with the router's current state.
    ///
    /// `peers` is every live, non-revoked `(MAC, key)` the certificate store
    /// holds; `revoked_macs` is every MAC the node currently holds a revocation
    /// for. The stale set is derived from both: a revoked MAC contributes
    /// whatever key it was last known by, and a MAC whose key *changed*
    /// contributes the key it moved away from.
    ///
    /// Wholesale replacement rather than a merge, because the certificate store
    /// is the authority on what is currently known: a peer whose certificate
    /// expired must *leave* the view, and a merge would keep resolving it.
    ///
    /// The generation only advances when something actually changed, so a
    /// carrier that reconciles on change is not woken by every poll.
    ///
    /// A poisoned lock is recovered rather than propagated. The only writer is
    /// this method and readers copy values out, so no invariant spans a panic;
    /// refusing to publish would degrade routing over a bookkeeping failure.
    pub fn publish(
        &self,
        identity: Option<[u8; 32]>,
        ca_endpoint: Option<String>,
        peers: impl IntoIterator<Item = (Mac, [u8; 32])>,
        revoked_macs: impl IntoIterator<Item = Mac>,
    ) {
        let fresh: HashMap<Mac, [u8; 32]> = peers.into_iter().collect();
        let revoked: HashSet<Mac> = revoked_macs.into_iter().collect();

        let mut guard = match self.state.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Supersession: a MAC that used to answer with one key and now answers
        // with another. Read before `known` is updated, so `known` is still the
        // previous answer.
        let mut stale: HashSet<[u8; 32]> = guard.stale.clone();
        for (mac, key) in &fresh {
            if let Some(previous) = guard.known.get(mac)
                && previous != key
            {
                stale.insert(*previous);
            }
        }
        // Revocation names a MAC; the key it condemns is whatever that MAC was
        // last known by.
        for mac in &revoked {
            if let Some(key) = guard.known.get(mac) {
                stale.insert(*key);
            }
        }

        // A key that is *currently* certified for some MAC is not stale,
        // whatever it used to be. This is what makes rotating back to a former
        // key recoverable instead of permanently self-blocking.
        let live: HashSet<[u8; 32]> = fresh.values().copied().collect();
        stale.retain(|k| !live.contains(k));
        while stale.len() > MAX_STALE_KEYS {
            // Order is unspecified; see `MAX_STALE_KEYS` for why dropping an
            // arbitrary entry at this bound is acceptable.
            let Some(&victim) = stale.iter().next() else {
                break;
            };
            stale.remove(&victim);
        }

        // Remember the current answers, then forget every MAC that is neither
        // certified nor revoked — bounding this map to what the router itself
        // is tracking.
        guard.known.extend(fresh.iter().map(|(m, k)| (*m, *k)));
        guard
            .known
            .retain(|mac, _| fresh.contains_key(mac) || revoked.contains(mac));

        let changed = guard.peers != fresh
            || guard.stale != stale
            || guard.identity != identity
            || guard.ca_endpoint != ca_endpoint;
        guard.identity = identity;
        guard.ca_endpoint = ca_endpoint;
        guard.peers = fresh;
        guard.stale = stale;
        drop(guard);

        if changed {
            self.generation.send_modify(|g| *g += 1);
        }
    }

    /// This node's own identity seed, or `None` while it has none.
    ///
    /// A carrier whose address is a key binds its endpoint to this, and is
    /// dormant until it exists — see the field docs for why waiting is right
    /// rather than binding to whatever the node generated at boot.
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.read(|s| s.identity)
    }

    /// Where the authority is reachable on the mesh, if enrolment recorded it.
    ///
    /// A key-addressed carrier dials this on every bind, alongside whatever its
    /// config named — see the field docs for why it is the more important of
    /// the two.
    pub fn ca_endpoint(&self) -> Option<String> {
        self.read(|s| s.ca_endpoint.clone())
    }

    /// The public key certified for `mac`, or `None` if this node holds no
    /// verified, unrevoked certificate for it.
    ///
    /// `None` means "no information", not "unreachable" — see the module docs.
    pub fn resolve(&self, mac: Mac) -> Option<[u8; 32]> {
        self.read(|s| s.peers.get(&mac).copied())
    }

    /// Whether `key` is one a carrier must not keep a connection to: revoked,
    /// or superseded by a re-key on the same MAC.
    pub fn is_stale(&self, key: &[u8; 32]) -> bool {
        self.read(|s| s.stale.contains(key))
    }

    /// Every currently stale key, for a carrier sweeping its connection table.
    pub fn stale_keys(&self) -> Vec<[u8; 32]> {
        self.read(|s| s.stale.iter().copied().collect())
    }

    /// The current generation. Advances only when a publish changed something,
    /// so a carrier can skip reconciling with a single integer comparison.
    pub fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    /// A receiver that becomes ready when the generation advances, for a
    /// carrier that wants to react rather than poll.
    pub fn watch(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// How many peers the view currently maps.
    pub fn len(&self) -> usize {
        self.read(|s| s.peers.len())
    }

    /// Whether the view maps no peers at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read under the lock, recovering from poisoning — see [`Self::publish`].
    fn read<T>(&self, f: impl FnOnce(&AuthState) -> T) -> T {
        match self.state.read() {
            Ok(g) => f(&g),
            Err(poisoned) => f(&poisoned.into_inner()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn an_empty_view_resolves_nothing() {
        let view = AuthView::new();
        assert!(view.is_empty());
        assert_eq!(view.resolve(mac(1)), None);
        assert!(!view.is_stale(&key(1)));
    }

    #[test]
    fn a_published_peer_resolves() {
        let view = AuthView::new();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert_eq!(view.resolve(mac(1)), Some(key(7)));
        assert_eq!(view.len(), 1);
    }

    /// Publishing replaces rather than merges: a peer whose certificate is
    /// gone must stop resolving, or an evicted node stays addressable forever.
    #[test]
    fn publishing_replaces_the_previous_contents() {
        let view = AuthView::new();
        view.publish(
            Some([1u8; 32]),
            None,
            [(mac(1), key(7)), (mac(2), key(8))],
            [],
        );
        view.publish(Some([1u8; 32]), None, [(mac(2), key(8))], []);

        assert_eq!(view.resolve(mac(1)), None, "a dropped peer stops resolving");
        assert_eq!(view.resolve(mac(2)), Some(key(8)));
        assert_eq!(view.len(), 1);
    }

    /// Every handle sees one view — the property that lets the driver publish
    /// and a carrier read without either holding the other.
    #[test]
    fn clones_share_one_view() {
        let view = AuthView::new();
        let reader = view.clone();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert_eq!(reader.resolve(mac(1)), Some(key(7)));
    }

    /// A revocation names a **MAC**; the router evicts the cached certificate
    /// when it ingests one, so the condemned *key* is only recoverable from
    /// what the view remembered. Without that memory a carrier could never be
    /// told which connection to close.
    #[test]
    fn a_revoked_macs_last_known_key_goes_stale() {
        let view = AuthView::new();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert!(!view.is_stale(&key(7)));

        // The node is revoked: it leaves `peers` (the driver filters it) and
        // arrives in the revoked set, with no key attached.
        view.publish(Some([1u8; 32]), None, [], [mac(1)]);

        assert_eq!(view.resolve(mac(1)), None, "it no longer resolves");
        assert!(view.is_stale(&key(7)), "and its key is closable");
    }

    /// The live-rotation path: a peer re-keys, so the key it moved away from
    /// must have its connection closed — otherwise the old connection shadows
    /// the new identity.
    #[test]
    fn a_rekeyed_peers_previous_key_goes_stale() {
        let view = AuthView::new();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        view.publish(Some([1u8; 32]), None, [(mac(1), key(9))], []);

        assert_eq!(view.resolve(mac(1)), Some(key(9)), "the new key is current");
        assert!(view.is_stale(&key(7)), "the old one is closable");
        assert!(!view.is_stale(&key(9)));
    }

    /// A key that is current for *some* MAC is never stale, whatever it was
    /// before. Without this, rotating back to a former key would leave it
    /// permanently unusable.
    #[test]
    fn a_key_that_becomes_current_again_stops_being_stale() {
        let view = AuthView::new();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        view.publish(Some([1u8; 32]), None, [(mac(1), key(9))], []);
        assert!(view.is_stale(&key(7)));

        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert!(!view.is_stale(&key(7)), "current again, so not closable");
        assert_eq!(view.resolve(mac(1)), Some(key(7)));
    }

    /// The authority's endpoint survives a publish and participates in the
    /// change signal — the field this type exists to carry, and the one whose
    /// silent loss would leave a link with nothing to dial.
    #[test]
    fn the_authority_endpoint_round_trips_and_signals() {
        let view = AuthView::new();
        assert_eq!(view.ca_endpoint(), None);

        let before = view.generation();
        view.publish(Some(key(1)), Some("ca@1.2.3.4:6001".into()), [], []);
        assert_eq!(view.ca_endpoint().as_deref(), Some("ca@1.2.3.4:6001"));
        assert!(view.generation() > before, "learning it is a change");

        let after = view.generation();
        view.publish(Some(key(1)), Some("ca@1.2.3.4:6001".into()), [], []);
        assert_eq!(view.generation(), after, "republishing it is not");
    }

    /// The generation is what a carrier reconciles on, so a publish that
    /// changed nothing must not advance it — otherwise every poll would sweep
    /// every connection table on the node.
    #[test]
    fn the_generation_advances_only_on_a_real_change() {
        let view = AuthView::new();
        let start = view.generation();

        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        let after_first = view.generation();
        assert!(after_first > start, "a new peer is a change");

        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert_eq!(
            view.generation(),
            after_first,
            "republishing identical state is not a change"
        );

        view.publish(Some([1u8; 32]), None, [(mac(1), key(9))], []);
        assert!(view.generation() > after_first, "a re-key is a change");
    }

    /// A watcher is woken by a change and not by a no-op republish.
    #[tokio::test]
    async fn a_watcher_is_notified_on_change() {
        let view = AuthView::new();
        let mut rx = view.watch();
        assert!(!rx.has_changed().unwrap(), "nothing has happened yet");

        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert!(rx.has_changed().unwrap(), "a new peer wakes the watcher");
        assert!(*rx.borrow_and_update() > 0);

        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        assert!(
            !rx.has_changed().unwrap(),
            "an identical republish does not"
        );
    }

    /// The `known` map is what makes a revoked key recoverable, and it must not
    /// grow with every node ever seen — it is pruned to what the router still
    /// tracks.
    #[test]
    fn forgotten_peers_do_not_leave_a_key_behind() {
        let view = AuthView::new();
        view.publish(Some([1u8; 32]), None, [(mac(1), key(7))], []);
        // `mac(1)` leaves without being revoked — an expired certificate, say.
        view.publish(Some([1u8; 32]), None, [], []);
        // Revoking it *now* has no key to condemn, because the view stopped
        // tracking it when it stopped being either certified or revoked.
        view.publish(Some([1u8; 32]), None, [], [mac(1)]);
        assert!(
            !view.is_stale(&key(7)),
            "a MAC dropped cleanly leaves nothing behind to go stale later"
        );
    }

    /// The stale set is bounded, so a long-lived node cannot accumulate keys
    /// without limit.
    #[test]
    fn the_stale_set_is_bounded() {
        let view = AuthView::new();
        for i in 0..(MAX_STALE_KEYS + 50) {
            let m = Mac([0, 0, 0, 0, (i >> 8) as u8, i as u8]);
            // Publish a key, then re-key the same MAC, superseding the first.
            view.publish(Some([1u8; 32]), None, [(m, [(i % 251) as u8; 32])], []);
            view.publish(
                Some([1u8; 32]),
                None,
                [(m, [((i + 1) % 251) as u8; 32])],
                [],
            );
        }
        assert!(
            view.stale_keys().len() <= MAX_STALE_KEYS,
            "stale set grew past its bound: {}",
            view.stale_keys().len()
        );
    }
}
