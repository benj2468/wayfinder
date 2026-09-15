//! The routing state the control plane borrows in order to *address* a frame.
//!
//! Every exchange in this module — a cert fetch, a renewal, a parked reply —
//! ends the same way: a body this module built, wrapped in a BATMAN header,
//! handed to the neighbour that is the next hop toward some distant node. The
//! first two halves are auth's; the third is the routing engine's, and this
//! trait is the whole of what auth needs to borrow to finish the job.
//!
//! It is deliberately three read-only questions and not a handle to the
//! engine. Auth must be able to *ask* where a node is and must not be able to
//! change what the engine believes: installing a route, crediting a proof and
//! ageing a path are the engine's decisions, and a control-plane module that
//! could make them would be a second, unreviewed routing input.

use crate::BatmanEngine;
use core::time::Duration;
use interfaces::frame::Mac;

/// The routing facts a control-plane exchange needs to address a frame.
///
/// Implemented by [`BatmanEngine`]; the router hands out `&self.batman`
/// alongside `self.auth.as_mut()`, which the borrow checker accepts because
/// they are disjoint fields.
///
/// The two next-hop questions are **not** interchangeable, and which one a
/// call site asks is a security decision — see
/// [`next_hop_unproven_ok`](Self::next_hop_unproven_ok).
pub trait Paths {
    /// This node's own mesh address.
    fn self_ident(&self) -> Mac;

    /// The best next hop toward `dest` as of `now`, or `None` when no live,
    /// *proven* path exists.
    ///
    /// The gate every directed frame clears, and the default for anything this
    /// module sends.
    ///
    /// **Proof is not key possession**, and an earlier version of this comment
    /// said it was. This node can hold a pairwise key for a neighbour that has
    /// never answered a challenge — the key comes from a verified certificate,
    /// the proof from the engine's own challenge table — so "unproven" does not
    /// mean "untaggable". What makes the gate right here is simply that a
    /// renewal is a directed sub-type carrying a pairwise tag
    /// (`wayfinder_driver_core::required_proof` → `RequiredProof::Tag`), and a
    /// directed frame goes to a proven hop like any unicast.
    fn next_hop(&self, now: Duration, dest: Mac) -> Option<Mac>;

    /// The best next hop toward `dest` as of `now`, **ignoring the proof
    /// gate**.
    ///
    /// For the certificate-control plane alone, and a deliberate hole: a
    /// `CertReq`/`CertReply` is what *supplies* the certificate a neighbour's
    /// pairwise key is derived from, so the pair goes out untagged
    /// (`wayfinder_driver_core::required_proof` → `RequiredProof::None`) and
    /// gating it on proof would deadlock bootstrap — nobody could prove
    /// anything because nobody could obtain the keys to prove with.
    ///
    /// **The rule, stated once**: this variant is correct exactly for the
    /// sub-types whose `required_proof` is `None`. Everything else — the data
    /// plane, and renewal, which by definition runs on a node that is already a
    /// credentialled routing member — takes [`next_hop`](Self::next_hop).
    ///
    /// Picking wrong in one direction deadlocks certificate distribution; in
    /// the other it hands renewal traffic to an unproven relay. The two methods
    /// have identical signatures, so only the call site's choice separates
    /// them — `auth/distribution.rs` is the only caller of this one.
    fn next_hop_unproven_ok(&self, now: Duration, dest: Mac) -> Option<Mac>;
}

impl<const O: usize, const I: usize, const M: usize, const L: usize> Paths
    for BatmanEngine<O, I, M, L>
{
    fn self_ident(&self) -> Mac {
        self.self_ident
    }

    fn next_hop(&self, now: Duration, dest: Mac) -> Option<Mac> {
        BatmanEngine::next_hop(self, now, dest)
    }

    fn next_hop_unproven_ok(&self, now: Duration, dest: Mac) -> Option<Mac> {
        BatmanEngine::next_hop_unproven_ok(self, now, dest)
    }
}
