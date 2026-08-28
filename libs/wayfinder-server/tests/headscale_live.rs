//! Exercises the Headscale REST client against a **real** Headscale server.
//!
//! Ignored by default: it needs a live server, so it is not part of an ordinary
//! `cargo nextest run`. Run it against one with
//!
//! ```text
//! WAYFINDER_HEADSCALE_URL=http://127.0.0.1:8080 \
//! WAYFINDER_HEADSCALE_KEY_FILE=/path/to/api.key \
//!   cargo nextest run -p wayfinder-server --test headscale_live -- --ignored
//! ```
//!
//! It exists because the parts of this client that can be wrong are exactly the
//! parts a mock cannot catch: whether `user` is a name or a numeric id, whether
//! an id arrives as a string or a number, whether deleting a user takes its
//! unspent keys with it. The unit tests cover the logic above the wire; this
//! covers the wire. `nix/tests/ca-provider.nix` runs the same shape of check
//! against a Headscale started by the NixOS module, which is what guards the
//! version the deployment actually pins.
//!
//! What it cannot cover, no matter which live server it is pointed at: anything
//! needing a node to have *registered*. That takes a real `tailscaled`, which a
//! cargo test has no way to bring up. This file used to claim it checked
//! "whether deleting a user takes its nodes with it" — it does not, and the
//! answer turned out to be no for exactly the nodes this system creates (#27:
//! a tagged node belongs to the synthetic `tagged-devices` user, not to its
//! MAC's). `nix/tests/vpn-data-plane.nix` is where a registered node is
//! revoked.

// Panicking on a failed assertion *is* the reporting mechanism in a test, and
// every other integration test in this workspace opts out the same way.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder::interfaces::frame::Mac;
use wayfinder_server::vpn::HeadscaleConfig;
use wayfinder_server::vpn::HeadscaleCoordinator;
use wayfinder_server::vpn::VpnCoordinator;

/// Build a coordinator from the environment, or `None` to skip.
fn coordinator() -> Option<HeadscaleCoordinator> {
    let api_url = std::env::var("WAYFINDER_HEADSCALE_URL").ok()?;
    let api_key_path = std::env::var("WAYFINDER_HEADSCALE_KEY_FILE").ok()?;
    Some(
        HeadscaleCoordinator::new(&HeadscaleConfig {
            api_url,
            api_key_path,
            login_server: None,
            node_tag: "tag:wayfinder-node".into(),
            preauth_ttl_secs: 300,
        })
        .expect("building the coordinator"),
    )
}

/// The whole coordinator contract against a real server: mint, re-mint, list,
/// revoke, and revoke again.
#[tokio::test]
#[ignore = "needs a live Headscale server"]
async fn mints_revokes_and_is_idempotent() {
    let Some(vpn) = coordinator() else {
        eprintln!("skipping: WAYFINDER_HEADSCALE_URL / _KEY_FILE not set");
        return;
    };
    let mac = Mac([0x02, 0x00, 0x00, 0x00, 0xbe, 0xef]);
    // A leftover user from an earlier run would make the find-or-create path
    // below take its "find" branch on the first call, which is not the branch
    // this test means to exercise first.
    vpn.revoke(mac).await.expect("clearing any earlier run");

    // Minting twice must both succeed: the first creates this node's Headscale
    // user, the second finds it. A node retrying enrollment takes the second
    // path, and an implementation that only created would fail there.
    let first = vpn.enroll(mac).await.expect("first enrollment");
    assert!(
        first.preauth_key.starts_with("hskey-auth-"),
        "unexpected key shape: {}",
        first.preauth_key
    );
    let second = vpn.enroll(mac).await.expect("second enrollment");
    assert_ne!(
        first.preauth_key, second.preauth_key,
        "each enrollment must mint a fresh single-use key"
    );

    // The peer list must parse. No node has registered, so this MAC is absent;
    // what is being asserted is that the call round-trips, since a schema drift
    // in Headscale's node representation shows up here first.
    //
    // Note what this cannot reach: with no node registered there is nothing to
    // correlate, so the MAC↔peer join is *not* covered here — that needs a real
    // tailscaled to have spent one of the keys minted above. It is covered
    // instead by `a_tagged_peer_is_correlated_through_the_key_it_registered_with`
    // in `src/vpn.rs`, against a byte-accurate capture of this server's node
    // representation. That gap is how a dead correlation shipped: every live
    // assertion here passed while `vpn list` could not name a single peer.
    //
    // The same gap swallowed #27 a second time, one call further on: `revoke`
    // below removes a user that owns no node, so the case that was broken —
    // deleting a node that really registered — is never reached. Twice now, so
    // treat a green run of this file as evidence about the *wire format* only,
    // never about what happens to a node.
    let peers = vpn.peers().await.expect("listing peers");
    assert!(
        peers.iter().all(|p| p.mac != Some(mac)),
        "no node has registered yet"
    );

    // Revoking removes the user and its unspent keys, and revoking again
    // succeeds — the idempotence the half-completed-revoke retry path depends
    // on. Not the node half: see above.
    vpn.revoke(mac).await.expect("first revoke");
    vpn.revoke(mac)
        .await
        .expect("revoking an absent peer is success, not an error");
}
