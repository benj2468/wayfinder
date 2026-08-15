{ pkgs, src, ... }:
with pkgs.craneLib;
let
  protoFilter = path: type: builtins.match ".*proto$" path != null;
  # `bins/wayfinder-web`'s stylesheet is a build input to `cargo leptos`, and
  # `filterCargoSources` keeps only Rust/Cargo files — without this the web
  # package builds against a missing stylesheet.
  webAssetFilter = path: type: builtins.match ".*\\.(css|html|ico|svg|png|woff2)$" path != null;
  commonArgs = {
    # We should add more filters here... we only need cargo files, protos, and rust files. No need for nix files.
    src = pkgs.lib.cleanSourceWith {
      inherit src;
      filter =
        path: type: (filterCargoSources path type) || (protoFilter path type) || (webAssetFilter path type);
      name = "wayfinder-src"; # Be reproducible, regardless of the directory name
    };
    # This is just the name for the workspace pre-build. It will be overwritten by each package;
    pname = "wayfinder-workspace";
    version = "0.1.0";
    nativeBuildInputs = with pkgs; [
      protobuf
      pkg-config
    ];
    buildInputs = with pkgs; [
      dbus
    ];
  };

  cargoArtifacts = buildDepsOnly commonArgs;

  mkWayfinderPkg =
    pname:
    buildPackage (
      commonArgs
      // {
        inherit cargoArtifacts pname;
        cargoExtraArgs = "-p ${pname}";
        doCheck = false;
      }
    );

  wayfinder-tap = mkWayfinderPkg "wayfinder-tap";
  wayfinder-tui = mkWayfinderPkg "wayfinder-tui";
  wayfinder-ctl = mkWayfinderPkg "wayfinder-ctl";

  # The web dashboard is built by `cargo-leptos`, not plain `cargo`, because it
  # compiles the crate twice: the axum server for the host and a hydration
  # bundle for wasm32. That needs a toolchain carrying wasm32's `rust-std`,
  # which nixpkgs' rustc does not — so this package gets its own crane
  # instance rather than switching the toolchain under `tap`/`tui`/`ctl` and
  # rebuilding all of them.
  # Stable, not the devShell's nightly: nightly 1.99 hits an internal compiler
  # error building tokio at `opt-level=3`, which is exactly what the release
  # build this package performs does. Nothing here needs nightly.
  webToolchain = pkgs.fenix.combine [
    (pkgs.fenix.stable.withComponents [
      "cargo"
      "rustc"
      "rust-src"
    ])
    pkgs.fenix.targets.wasm32-unknown-unknown.stable.rust-std
  ];
  craneLibWeb = pkgs.craneLib.overrideToolchain webToolchain;

  wayfinder-web = craneLibWeb.buildPackage (
    commonArgs
    // {
      pname = "wayfinder-web";
      # Deliberately not sharing `cargoArtifacts`: those were built by a
      # different toolchain and for the host target only, so they are of no use
      # to the wasm half and cannot be reused across toolchains anyway.
      cargoArtifacts = craneLibWeb.buildDepsOnly (
        commonArgs
        // {
          pname = "wayfinder-web-deps";
          cargoExtraArgs = "-p wayfinder-web --features ssr";
        }
      );
      doCheck = false;

      # `buildPhaseCargoCommand` below runs `cargo leptos build`, not plain
      # `cargo build --message-format json-render-diagnostics`, so crane's
      # `installFromCargoBuildLogHook` has no `$cargoBuildLog` to work from.
      # Installation is handled explicitly by `installPhaseCommand` instead.
      doNotPostBuildInstallCargoBinaries = true;

      nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
        pkgs.cargo-leptos
        # Generates the JS glue. Pinned to match the `wasm-bindgen` crate pin in
        # `bins/wayfinder-web/Cargo.toml`; wasm-bindgen refuses to run on a
        # version mismatch, so the two move together.
        pkgs.wasm-bindgen-cli_0_2_126
        # `wasm-opt`, which cargo-leptos shells out to for release bundles.
        pkgs.binaryen
        pkgs.makeWrapper
      ];

      # cargo-leptos writes caches under $HOME, which the sandbox does not set.
      buildPhaseCargoCommand = ''
        export HOME=$TMPDIR
        cargo leptos build --release
      '';

      # The binary alone is not runnable: it serves a bundle cargo-leptos emits
      # under `target/site` and locates at runtime through the `LEPTOS_*`
      # environment. Installing the bundle and baking those paths into a wrapper
      # is what makes the package self-contained — `wayfinder-web` on a PATH just
      # works, with no environment for the caller to get right.
      installPhaseCommand = ''
        mkdir -p $out/bin $out/share/wayfinder-web
        cp -r target/site $out/share/wayfinder-web/site

        install -Dm755 target/release/wayfinder-web $out/bin/.wayfinder-web-unwrapped
        makeWrapper $out/bin/.wayfinder-web-unwrapped $out/bin/wayfinder-web \
          --set-default LEPTOS_SITE_ROOT "$out/share/wayfinder-web/site" \
          --set-default LEPTOS_SITE_PKG_DIR "pkg" \
          --set-default LEPTOS_OUTPUT_NAME "wayfinder-web"
      '';
    }
  );
in
{
  inherit
    wayfinder-tap
    wayfinder-tui
    wayfinder-ctl
    wayfinder-web
    ;
}
