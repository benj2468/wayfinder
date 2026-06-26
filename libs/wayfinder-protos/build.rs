fn main() {
    let mut config = prost_build::Config::new();

    // Force the generator to use BTreeMap instead of HashMap
    config.btree_map(["."]);

    // Feature-gated `serde::Serialize` on every generated type, so a host build
    // with the `serde` feature can emit responses as JSON while the default
    // (no_std) build derives nothing extra.
    config.type_attribute(
        ".",
        "#[cfg_attr(feature = \"serde\", derive(serde::Serialize))]",
    );

    config
        .compile_protos(&["protos/wayfinder/v1alpha/wayfinder.proto"], &["protos/"])
        .expect("failed to compile protos");
}
