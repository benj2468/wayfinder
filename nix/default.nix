{ pkgs, src, ... }:
let
  # One toolchain for every package here, deliberately.
  #
  # crane keys `cargoArtifacts` on the toolchain, so two toolchains mean two
  # full compiles of the same lockfile. Of the 507 packages in `Cargo.lock`,
  # 404 are reachable from tap/tui/ctl and 387 from the web dashboard — 298 of
  # them from both. Building the host binaries against nixpkgs' rustc and the
  # dashboard against a fenix one paid for those 298 twice.
  #
  # `bins/wayfinder-web` is what constrains the choice: `cargo leptos` compiles
  # it twice, once for the host and once for wasm32, and nixpkgs' rustc carries
  # no wasm32 `rust-std`. So everything builds on a fenix toolchain that has
  # one, and the host binaries share the dashboard's dependency layer rather
  # than growing a second one.
  #
  # Stable, not the devShell's nightly: nightly 1.99 hits an internal compiler
  # error building tokio at `opt-level=3`, which is exactly what the release
  # builds here perform. Nothing here needs nightly.
  toolchain = pkgs.fenix.combine [
    pkgs.fenix.stable.minimalToolchain
    pkgs.fenix.targets.wasm32-unknown-unknown.stable.rust-std
  ];

  craneLib = pkgs.craneLib.overrideToolchain toolchain;
in
with craneLib;
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

  # One dependency layer for every package below, host target only.
  #
  # Carrying the wasm32 dependencies that `bins/wayfinder-web`'s hydration half
  # needs was tried twice and abandoned; crane's artifact model does not hold
  # two targets in one layer. Chaining a wasm-scoped `buildDepsOnly` onto this
  # one pruned the inherited host artifacts from 2351 `release/deps` entries to
  # 289, so web recompiled its `ssr` half: 450 crates in-derivation, against 313
  # with no wasm layer at all. Running the wasm build from this derivation's
  # `postBuild` fared worse still — no wasm artifacts survived into the output
  # (0 entries) and the host half fell to 1237, degrading tap/tui/ctl too.
  #
  # So the hydration half's dependencies are compiled inside the `wayfinder-web`
  # derivation on every build. That is the remaining known waste here.
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
  # bundle for wasm32. Both halves come out of the same `craneLib` as
  # tap/tui/ctl — see the toolchain note at the top for why that is one
  # toolchain and not two.
  wayfinder-web = buildPackage (
    commonArgs
    // {
      pname = "wayfinder-web";
      # The same layer tap/tui/ctl use. It covers this crate's host (`ssr`) half;
      # the wasm32 half is a different target and is not in there, so
      # `cargo leptos` recompiles its dependencies here — see the note on
      # `cargoArtifacts` for why that is not cached.
      inherit cargoArtifacts;
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
