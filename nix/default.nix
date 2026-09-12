{
  pkgs,
  src,
  # The build identity to bake into each binary, from flake metadata. Optional
  # so a plain `callPackage ./nix {}` still works: `null` leaves
  # `wayfinder-version`'s build script to fall back on its own (which, with no
  # `.git` in the store source, means it reports "unknown").
  buildVersion ? null,
  # The full commit, alongside the above — see `flake.nix` for why both.
  buildCommit ? null,
  ...
}:
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

  # Deliberately *not* part of `commonArgs`: `cargoArtifacts` above is the
  # `buildDepsOnly` shared by the plain-cargo packages (`wayfinder-web` builds
  # its own, further down), and a revision-dependent variable there would change
  # its derivation hash on every commit, throwing away the dependency cache each
  # time. Workspace crates are compiled by `buildPackage` anyway, which is the
  # only stage that needs this.
  buildVersionEnv =
    pkgs.lib.optionalAttrs (buildVersion != null) {
      WAYFINDER_BUILD_VERSION = buildVersion;
    }
    // pkgs.lib.optionalAttrs (buildCommit != null) {
      WAYFINDER_BUILD_COMMIT = buildCommit;
    };

  mkWayfinderPkg =
    pname:
    buildPackage (
      commonArgs
      // buildVersionEnv
      // {
        inherit cargoArtifacts pname;
        cargoExtraArgs = "-p ${pname}";
        doCheck = false;
      }
    );

  wayfinder-tap = mkWayfinderPkg "wayfinder-tap";
  wayfinder-tui = mkWayfinderPkg "wayfinder-tui";
  wayfinder-ctl = mkWayfinderPkg "wayfinder-ctl";

  # The Wireshark/tshark Lua dissector (`libs/wayfinder-shark`), packaged as a
  # plugin *directory* rather than a bare file, so anything that scans one
  # finds it. Nothing but the `.lua` lands in the output; the build input is
  # the whole filtered source, so this re-copies its one file on any repo
  # change, which costs a second.
  wayfinder-shark = pkgs.runCommandLocal "wayfinder-shark" { } ''
    install -Dm444 ${src}/libs/wayfinder-shark/wayfinder.lua \
      $out/lib/wireshark/plugins/wayfinder.lua
  '';

  # `tshark` and `termshark` with the dissector already loaded.
  #
  # Wireshark finds its global plugin directory by walking up from the *real*
  # path of the running executable (`PLUGIN_DIR` is compiled in relative to an
  # install prefix, and the prefix is derived from `/proc/self/exe`), so this
  # copies the tshark binary into a prefix of our own whose
  # `lib/wireshark/plugins` holds Wireshark's plugins *and* ours. A copy, not a
  # symlink and not a wrapper: a symlink resolves back to Wireshark's own
  # prefix, which is the one place we cannot add a file to.
  #
  # The tidier-looking `WIRESHARK_PLUGIN_DIR` does not work here, and fails in
  # the case this exists for. Wireshark ignores every path environment variable
  # when it starts with special privileges, and `started_with_special_privs()`
  # counts a real uid of 0 (`wsutil/privileges.c`) — so the variable is honoured
  # for an ordinary user and silently dropped for the root shell an operator
  # debugging a node is usually sitting in. `nix/tests/simple.nix` asserts the
  # root case for that reason.
  #
  # `-X lua_script:` is out for the same reason, one level up: user scripts sit
  # behind the same privilege gate (`epan/wslua/init_wslua.c`), while the global
  # plugin directory is loaded unconditionally.
  #
  # Both are `hiPrio` because they install binaries under the stock names: a
  # system that also pulls in plain `wireshark-cli`
  # (`programs.wireshark.enable`) or `termshark` would otherwise resolve the
  # collision by whichever landed in `environment.systemPackages` first, and
  # silently hand the operator a tshark that decodes mesh frames as an
  # unstructured `eth` payload.
  wayfinder-tshark = pkgs.lib.hiPrio (
    pkgs.runCommandLocal "wayfinder-tshark" { } ''
      mkdir -p $out/bin $out/lib/wireshark/plugins

      # The whole CLI suite, so this package stands in for `wireshark-cli`
      # rather than beside it. `dumpcap` is not optional company: tshark spawns
      # it for every live capture and nixpkgs patches the lookup to go through
      # `PATH` first (`lookup-dumpcap-in-path.patch`, so a setcap wrapper can
      # win), falling back to this prefix. A node that installs a lone tshark
      # has it in neither place, and every `tshark -i` there dies with
      # "Couldn't run dumpcap in child process: No such file or directory".
      #
      # These stay symlinks and so resolve against Wireshark's own prefix,
      # which is right for all of them: `dumpcap` and friends do not dissect.
      # `rawshark`/`sharkd` do, and do not see the dissector for the same
      # reason — nothing here drives them.
      ln -s ${pkgs.wireshark-cli}/bin/* $out/bin/

      # tshark itself has to be a real copy living in *this* prefix. Removed
      # first because `cp` over the symlink would write through it, into a
      # read-only store path.
      rm $out/bin/tshark
      cp ${pkgs.wireshark-cli}/bin/tshark $out/bin/tshark

      # The rest of the prefix tshark resolves against — its data files and its
      # extcap helpers — is shared with the package the binary came from.
      ln -s ${pkgs.wireshark-cli}/share $out/share
      ln -s ${pkgs.wireshark-cli}/libexec $out/libexec

      # Wireshark's own plugins (the versioned subdirectory of dissector,
      # codec and wiretap `.so`s) alongside the dissector. Linking only ours
      # would take Wireshark's off the search path with it.
      ln -s ${pkgs.wireshark-cli}/lib/wireshark/plugins/* $out/lib/wireshark/plugins/
      ln -s ${wayfinder-shark}/lib/wireshark/plugins/wayfinder.lua $out/lib/wireshark/plugins/
    ''
  );

  # termshark shells out to `tshark` for every decode and finds it on `PATH`,
  # so it needs no plugin knowledge of its own — only ours ahead of the plain
  # one its own nixpkgs wrapper appends.
  wayfinder-termshark = pkgs.lib.hiPrio (
    pkgs.runCommandLocal "wayfinder-termshark" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
      makeWrapper ${pkgs.termshark}/bin/termshark $out/bin/termshark \
        --prefix PATH : ${wayfinder-tshark}/bin
    ''
  );

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
    // buildVersionEnv
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
    wayfinder-shark
    wayfinder-tshark
    wayfinder-termshark
    ;
}
