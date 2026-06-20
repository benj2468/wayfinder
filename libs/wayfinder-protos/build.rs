fn main() {
    let mut config = prost_build::Config::new();

    // Force the generator to use BTreeMap instead of HashMap
    config
        .btree_map(["."])
        .compile_protos(&["protos/wayfinder/v1alpha/wayfinder.proto"], &["protos/"])
        .expect("failed to compile protos");
}
