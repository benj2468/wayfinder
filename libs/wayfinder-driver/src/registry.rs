//! Compile-time registry of link builders.
//!
//! A link type — whether it ships in-tree (`Udp`, `RawIp`, `RawL2`) or comes
//! from a third-party crate — becomes available to the config-driven host
//! loop by registering a [`LinkBuilder`] into [`LINK_BUILDERS`], rather than
//! by editing a closed `match` in `wayfinder-tap`. A customer adds a
//! proprietary link type by depending on their own crate (which registers
//! into this same slice) from their own build of `wayfinder-tap` — no change
//! to this workspace required.
//!
//! **Linker caveat:** a crate that is only depended on for its
//! `#[distributed_slice(LINK_BUILDERS)]` registration, and never otherwise
//! referenced, can be dead-code-eliminated by the linker in a release/LTO
//! build, silently dropping the registration. A customer adding a
//! third-party link crate should force-reference something from it (e.g. a
//! `let _ = thirdparty_link::REGISTER;` in `main.rs`) to guarantee it stays
//! linked in.

use std::future::Future;
use std::pin::Pin;

use tokio::task::JoinSet;

use wayfinder::link::DynLinkT;

/// The future a [`LinkBuilder::build`] function returns: builds a live link
/// from that link type's `params`, borrowing them (and the caller's
/// `JoinSet`) only for the duration of the build.
pub type BuildFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Box<DynLinkT<'static>>>> + Send + 'a>>;

/// One registered link type.
///
/// Third-party link crates register their own `LinkBuilder` into
/// [`LINK_BUILDERS`] via `#[linkme::distributed_slice(LINK_BUILDERS)]`.
pub struct LinkBuilder {
    /// The `type:` tag this builder claims, matched against
    /// [`LinkConfig::link_type`](wayfinder::config::LinkConfig::link_type).
    pub type_tag: &'static str,
    /// Build a live link from this link type's `params`, spawning any
    /// background bridge task into the given `JoinSet` (its lifetime is tied
    /// to the caller's, matching the existing `build_udp_link`-style
    /// helpers).
    pub build:
        for<'a> fn(&'a serde_json::Value, &'a mut JoinSet<anyhow::Result<()>>) -> BuildFuture<'a>,
    /// The JSON Schema of this link type's `params`, folded into
    /// [`crate::schema::config_schema`] so a build documents exactly the
    /// link types actually compiled into it.
    pub schema: fn() -> schemars::Schema,
}

/// Every link type compiled into this binary, keyed by [`LinkBuilder::type_tag`].
#[linkme::distributed_slice]
pub static LINK_BUILDERS: [LinkBuilder];

#[cfg(test)]
mod tests {
    use super::*;
    use linkme::distributed_slice;

    #[distributed_slice(LINK_BUILDERS)]
    static DUMMY: LinkBuilder = LinkBuilder {
        type_tag: "__test_dummy_link",
        build: |_params, _join_set| Box::pin(async { Err(anyhow::anyhow!("dummy build")) }),
        schema: || schemars::json_schema!({ "type": "object" }),
    };

    /// A registered builder is discoverable by its `type_tag`.
    #[test]
    fn registered_builder_is_found_by_tag() {
        assert!(
            LINK_BUILDERS
                .iter()
                .any(|b| b.type_tag == "__test_dummy_link")
        );
    }

    /// An unregistered tag is absent — callers use this to report a helpful
    /// "unknown link type" error rather than panicking.
    #[test]
    fn unregistered_tag_is_not_found() {
        assert!(
            !LINK_BUILDERS
                .iter()
                .any(|b| b.type_tag == "__nonexistent_link_type__")
        );
    }

    /// The registered build function is actually callable and runs to
    /// completion — proving `LINK_BUILDERS` holds live builders, not just
    /// metadata.
    #[tokio::test]
    async fn registered_builder_is_callable() {
        let builder = LINK_BUILDERS
            .iter()
            .find(|b| b.type_tag == "__test_dummy_link")
            .expect("dummy builder registered above");
        let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
        let result = (builder.build)(&serde_json::Value::Null, &mut join_set).await;
        assert!(result.is_err());
    }

    /// `LINK_BUILDERS` is a flat slice searched by `.find()`-on-`type_tag`
    /// (see `wayfinder-tap::main`), so two registrants sharing a tag would
    /// silently shadow one another — the second is unreachable and nothing
    /// reports the collision. Guard against that regressing unnoticed as
    /// more link types (in-tree or third-party) get registered.
    #[test]
    fn no_two_registered_builders_share_a_type_tag() {
        let mut tags: Vec<&str> = LINK_BUILDERS.iter().map(|b| b.type_tag).collect();
        let before = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(
            tags.len(),
            before,
            "LINK_BUILDERS has a duplicate type_tag: {tags:?}"
        );
    }
}
