{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix.url = "github:numtide/treefmt-nix";

    fenix.url = "github:nix-community/fenix";

    crane.url = "github:ipetkov/crane";

    git-hooks.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    inputs@{
      nixpkgs,
      flake-parts,
      fenix,
      ...
    }:
    let
      overlay = final: prev: {
        inherit (prev.callPackage ./nix { src = prev.lib.cleanSource ./.; })
          wayfinder-tap
          wayfinder-tui
          wayfinder-ctl
          ;
      };
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;

      imports = [
        inputs.treefmt-nix.flakeModule
        inputs.git-hooks.flakeModule
      ];

      flake = {

        overlays.default = overlay;

        nixosModules.default = ./nix/modules/wayfinder.nix;
      };

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          # Bare-metal target for the embedded (`no_std`) crates — currently
          # the nRF52840 (Cortex-M4F) that `libs/nrf-ieee802154` builds
          # against. Combined (not `withComponents`-ed) onto the host
          # toolchain below so `cargo build --target thumbv7em-none-eabihf`
          # picks up its prebuilt `core`/`alloc` without needing nightly's
          # `-Z build-std`.
          bareMetalTarget = "thumbv7em-none-eabihf";
          pixelTarget = "aarch64-linux-android";

          rustToolchain = pkgs.fenix.combine [
            (pkgs.fenix.complete.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
              "llvm-tools-preview"
            ])
            pkgs.fenix.targets.${bareMetalTarget}.latest.rust-std
            pkgs.fenix.targets.${pixelTarget}.latest.rust-std
          ];

          # Python interpreter with the integration-test deps (pytest). Used by
          # both the default dev shell and the lightweight `pytest` shell that
          # CI runs — see tests/README.md and .gitlab-ci.yml.
          pytestEnv = pkgs.python3.withPackages (ps: with ps; [ pytest ]);

          testPkgs = import nixpkgs {
            inherit system;
            overlays = [
              overlay
              (_final: prev: {
                craneLib = inputs.crane.mkLib prev;
              })

            ];
          };

        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              fenix.overlays.default
            ];
          };

          pre-commit.settings.hooks.treefmt.enable = true;

          devShells.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
            packages = with pkgs; [
              nil
              nixd
              rustToolchain
              cargo-nextest
              cargo-machete
              cargo-llvm-cov
              cargo-fuzz
              cargo-ndk
              rust-analyzer
              pytestEnv
              python312Packages.virtualenv
              maturin
              uv
              socat
              protobuf
              buf
              tshark
              glab
              stdenv.cc.cc.lib
              probe-rs-tools
              jdk17
              ktlint
            ];

            buildInputs = with pkgs; [ dbus ];

            nativeBuildInputs = with pkgs; [
              protobuf
              pkg-config
            ];

            shellHook = ''
              ${config.pre-commit.installationScript}
              PROJECT_ROOT=$(git rev-parse --show-toplevel)

              python3 -m venv ''${PROJECT_ROOT}/.venv

              source "''${PROJECT_ROOT}/.venv/bin/activate"

              python3 -m pip install --upgrade pip
              uv sync --only-dev

              # Manylinux wheels (numpy, matplotlib's C extensions — see
              # sim/scenarios/*.py's `uv sync --group sim`) expect libstdc++ on
              # the loader path; this shell's stdenv doesn't put it there by
              # default, so wire it up once here rather than per-invocation.
              export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:$LD_LIBRARY_PATH"
            '';
          };

          # Minimal shell for running the pytest integration suite (CI uses
          # this so it gets python + tshark without building the Rust toolchain).
          devShells.pytest = pkgs.mkShell {
            packages = [
              pytestEnv
              pkgs.tshark
            ];
          };

          # Android NDK + Gradle for bins/wayfinder-pixel/android, kept out of
          # devShells.default so the multi-GB download isn't pulled into
          # every ordinary `cargo build` session. Google ships no
          # linux-aarch64 host build of the NDK toolchain — this only works
          # once the host has qemu x86_64 emulation registered
          # (`boot.binfmt.emulatedSystems` on gantz) so those x86_64 ELF
          # binaries run transparently.
          #
          # Deliberately NDK-only for now (no SDK build-tools/platforms,
          # i.e. not `androidComposition.androidsdk`, just `.ndk-bundle`) —
          # that's all Phase 0 needs to get `cargo ndk` building. Pulling in
          # `androidenv`'s `build-tools` package turned out to unconditionally
          # need `pkgsi686Linux` (`ncurses`/`glibc`/`zlib`, for a legacy
          # 32-bit `aapt` it bundles) on any x86_64 host — see
          # `pkgs/development/mobile/androidenv/build-tools.nix` — which
          # isn't cached as a substitute and needs its own
          # `i686-linux`-capable builder, a second NixOS-level emulation
          # dependency beyond just `x86_64-linux`. Revisit when the Gradle
          # project (Phase 2) actually needs `aapt2`/`d8`: the Android
          # Gradle Plugin fetches its own `aapt2` via Maven, so
          # `androidenv`'s build-tools package (and its i686 dependency) may
          # not be needed at all — check that before reaching for
          # `buildToolsVersions`/`platformVersions` here again.
          #
          # `androidPkgsUnfree` is deliberately evaluated as `x86_64-linux`,
          # *not* this perSystem's own `system` (aarch64-linux) — the NDK
          # derivation calls `autoPatchelf` on Google's prebuilt x86_64
          # binaries against its `buildInputs` (zlib/libcxx/gcc-lib) to fix
          # up the interpreter/rpath from the generic `/lib64/ld-linux-...`
          # path those binaries assume to real Nix store paths. Evaluating
          # against the ambient aarch64-linux `pkgs` instead builds those
          # `buildInputs` for the wrong architecture: `autoPatchelf` checks
          # ELF-class compatibility before using a candidate, silently finds
          # no match, and leaves the interpreter unpatched — the derivation
          # still builds without error, but the resulting binaries fail at
          # *run* time under qemu with "Could not open
          # '/lib64/ld-linux-x86-64.so.2'" (confirmed by inspecting the built
          # NDK derivation's `buildInputs` after hitting exactly that error).
          # `nix derivation show` a `.drv` under this shell to re-verify
          # `buildInputs`/`system` are `x86_64-linux` if this ever regresses.
          devShells.android =
            let
              androidPkgsUnfree = import nixpkgs {
                system = "x86_64-linux";
                config.allowUnfree = true;
                config.android_sdk.accept_license = true;
              };
              androidComposition = androidPkgsUnfree.androidenv.composeAndroidPackages {
                includeNDK = true;
                ndkVersions = [ "27.2.12479018" ]; # r27c
              };
            in
            pkgs.mkShell {
              inputsFrom = [ config.devShells.default ];

              packages = [
                androidComposition.ndk-bundle
                pkgs.gradle
                pkgs.android-tools # adb, native aarch64, no emulation needed
              ];

              shellHook = ''
                export ANDROID_NDK_HOME="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle"
              '';
            };

          pre-commit = {
            check.enable = true;
          };

          packages = {
            inherit (testPkgs) wayfinder-tap wayfinder-tui wayfinder-ctl;
            wayfinder-simple = testPkgs.callPackage ./nix/tests/simple.nix { };
          };

          treefmt = {
            projectRootFile = "Cargo.toml";
            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              ruff-check.enable = true;
              ruff-format.enable = true;
              buf.enable = true;
              yamlfmt.enable = true;
              dockerfmt.enable = true;
              shellcheck.enable = true;
              stylua.enable = true;
            };

            settings.formatter.rustfmt =
              let
                cargoFmtWrapper = pkgs.writeShellApplication {
                  name = "treefmt-cargo-fmt";
                  runtimeInputs = [ rustToolchain ];
                  text = ''
                    cargo fmt -- "''$@"
                  '';
                };
              in
              {
                command = "${cargoFmtWrapper}/bin/treefmt-cargo-fmt";
                options = pkgs.lib.mkForce [ ];
                includes = [ "*.rs" ];
              };
          };
        };
    };
}
