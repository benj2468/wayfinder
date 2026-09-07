//! Build script: compiles the management-API protobuf definitions with `prost`,
//! deriving feature-gated `serde::Serialize`/`serde::Deserialize` on every
//! generated type.
#[allow(clippy::expect_used)]
fn main() {
    let mut config = prost_build::Config::new();

    // Force the generator to use BTreeMap instead of HashMap
    config.btree_map(["."]);

    // Feature-gated serde derives on every generated type, so a host build with
    // the `serde` feature can move responses across a JSON boundary while the
    // default (no_std) build derives nothing extra.
    //
    // Both directions, not just `Serialize`: `wayfinderctl --output json` only
    // ever encodes, but `wayfinder-web` sends a snapshot of these types from its
    // server to the browser and decodes it there.
    config.type_attribute(
        ".",
        "#[cfg_attr(feature = \"serde\", derive(serde::Serialize, serde::Deserialize))]",
    );

    // The renewal provider rides in a box, so `SetAuthRequest` — and through it
    // the `WayfinderRequest` enum every dispatcher returns by value — does not
    // grow by the size of a `String`, a `Vec` and a `String` for a field only
    // an enrollment sets. Without it the request enum crosses clippy's
    // `result_large_err` threshold and every `Result<_, WayfinderRequest>` in
    // `service.rs` becomes a lint error.
    config.boxed(".wayfinder.v1alpha.SetAuthRequest.provider");

    config
        .include_file("_includes.rs")
        .compile_protos(&["protos/wayfinder/v1alpha/wayfinder.proto"], &["protos/"])
        .expect("failed to compile protos");
}
