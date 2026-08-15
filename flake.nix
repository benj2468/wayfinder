{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    jetpack = {
      url = "github:anduril/jetpack-nixos/master";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      nixpkgs,
      flake-parts,
      fenix,
      jetpack,
      ...
    }:
    let
      overlay = final: prev: {
        craneLib = inputs.crane.mkLib prev;

        cudaPackages = final.cudaPackages_13_0;

        inherit (prev.callPackage ./nix { src = prev.lib.cleanSource ./.; })
          wayfinder-tap
          wayfinder-tui
          wayfinder-ctl
          wayfinder-web
          ;
      };

      nixpkgsForSystem =
        system:
        import inputs.nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            segger-jlink.acceptLicense = true;
            permittedInsecurePackages = [
              "segger-jlink-qt4-952"
            ];

            cudaSupport = true;
            cudaCapabilities = [ "8.7" ];
          };
          overlays = [
            # `nix/default.nix` reaches for `pkgs.fenix` to give the web
            # package a wasm32-capable toolchain; nixpkgs' own rustc carries
            # no wasm32 `rust-std`.
            fenix.overlays.default
            overlay
          ];
        };

      mkWayfinderSystem =
        name:
        {
          modules ? [ ],
        }:
        let
          dir = ./nix/machines + "/${name}";

          shared = [
            {
              nixpkgs = {
                overlays = [
                  fenix.overlays.default
                  overlay
                ];
                config.allowUnfree = true;
              };
            }
            (dir + "/common.nix")
          ]
          ++ modules;

          specialArgs = { inherit inputs; };

          # What actually lands on the disk. disko's module reads the same
          # layout the installer partitions from and derives `fileSystems`
          # from it, so the two cannot drift.
          installed = nixpkgs.lib.nixosSystem {
            inherit specialArgs;
            modules = shared ++ [
              inputs.disko.nixosModules.disko
              (dir + "/system.nix")
              (dir + "/disk.nix")
            ];
          };
        in
        {
          # The live USB installer. `nix/modules/installer.nix` puts the disk
          # layout, the built system and the `wayfinder-install` wrapper on the
          # image, so installing copies what is already on the stick onto the
          # NVMe — no flake checkout and no network on the board.
          ${name} = nixpkgs.lib.nixosSystem {
            inherit specialArgs;
            modules = shared ++ [
              ./nix/modules/installer.nix
              (dir + "/installer.nix")
              {
                wayfinder.installer = {
                  machine = name;
                  layout = (dir + "/disk.nix");
                  target = installed;
                };
              }
            ];
          };

          "${name}-system" = installed;
        };

      # The whole fleet: an attrset keyed by machine name, flattened into the
      # `<name>` / `<name>-system` pairs `nixosConfigurations` wants. Adding a
      # board is one attribute here plus its `nix/machines/<name>/` directory.
      mkWayfinderSystems =
        machines: nixpkgs.lib.mergeAttrsList (nixpkgs.lib.mapAttrsToList mkWayfinderSystem machines);
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

        # Each entry yields two configurations — `<name>` (the installer ISO)
        # and `<name>-system` (what that ISO installs). A new board is a line
        # here and a `nix/machines/<name>/` directory beside `orin-nano`.
        nixosConfigurations = mkWayfinderSystems {
          orin-nano.modules = [ jetpack.nixosModules.default ];
        };
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

          # Browser target for `bins/wayfinder-web`. `cargo-leptos` builds that
          # crate twice — the axum server for the host and a hydration bundle
          # for this target — so its `rust-std` is combined on for the same
          # reason the bare-metal one is.
          wasmTarget = "wasm32-unknown-unknown";

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
            pkgs.fenix.targets.${wasmTarget}.latest.rust-std
          ];

          # Python interpreter with the integration-test deps (pytest). Used by
          # both the default dev shell and the lightweight `pytest` shell that
          # CI runs — see tests/README.md and .gitlab-ci.yml.
          pytestEnv = pkgs.python3.withPackages (ps: with ps; [ pytest ]);

          nixpkgs = nixpkgsForSystem system;

          # nrfutil's package-generation extension (nrfutil-nrf5sdk-tools —
          # needed to build a DFU package for the nRF52840 dongle's probe-less
          # flashing flow, see `libs/wayfinder-nrf/CLAUDE.md`) isn't published
          # by Nordic for aarch64-linux, only x86_64-linux and darwin. Rather
          # than skip it on an aarch64 host, run the real x86_64 build under
          # qemu-user emulation — the same trick already used for x86_64-only
          # Android NDK/SDK binaries on this project's aarch64 devShell.
          pkgsX86 = nixpkgsForSystem "x86_64-linux";

          nrfutilX86 = pkgsX86.nrfutil.withExtensions [
            "nrfutil-device"
            "nrfutil-nrf5sdk-tools"
          ];
          # `nrfutil nrf5sdk-tools` under qemu-user: the wrapper script sets up
          # PATH/env vars a bare `qemu-x86_64 <the .nrfutil-wrapped ELF>` would
          # miss (it looks for a bundled legacy Python executable via PATH),
          # so run it as `bash <wrapper script>` under emulation instead of
          # the underlying binary directly.
          nrfutilNrf5sdkTools = pkgs.writeShellApplication {
            name = "nrfutil-nrf5sdk-tools";
            runtimeInputs = [ pkgs.qemu ];
            text = ''
              exec qemu-x86_64 "${pkgsX86.bash}/bin/bash" "${nrfutilX86}/bin/nrfutil" nrf5sdk-tools "$@"
            '';
          };

        in
        {
          _module.args.pkgs = nixpkgs;

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
              cargo-binutils
              # Build driver for `bins/wayfinder-web`: compiles the axum server
              # and the wasm hydration bundle together and serves them
              # (`cargo leptos watch`). `binaryen` supplies the `wasm-opt` it
              # shells out to for release bundles.
              cargo-leptos
              rust-analyzer
              binaryen
              # cargo-leptos shells out to `wasm-bindgen` to generate the JS
              # glue, and refuses to run if the CLI's version differs from the
              # `wasm-bindgen` crate's. Hence the exact-version attribute rather
              # than plain `wasm-bindgen-cli`: it is pinned in lockstep with the
              # `=0.2.126` in `bins/wayfinder-web/Cargo.toml`, and the two must
              # be bumped together.
              wasm-bindgen-cli_0_2_126
              pytestEnv
              python312Packages.virtualenv
              maturin
              uv
              socat
              protobuf
              buf
              tshark
              glab
              just
              stdenv.cc.cc.lib
              probe-rs-tools
              flip-link
              nrfutil.withAllExtensions
              nrf5-sdk
              nrf-command-line-tools
              nrfutilNrf5sdkTools
            ];

            buildInputs = with pkgs; [
              dbus
            ];

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
              uv sync --group dev --group sim

              # Manylinux wheels (numpy, matplotlib's C extensions — see
              # sim/scenarios/*.py's `uv sync --group sim`) expect libstdc++ on
              # the loader path; this shell's stdenv doesn't put it there by
              # default, so wire it up once here rather than per-invocation.
              export LD_LIBRARY_PATH="${
                pkgs.lib.makeLibraryPath [
                  pkgs.stdenv.cc.cc.lib
                  pkgs.zlib
                ]
              }"

              export PATH=/run/wrappers/bin:$PATH
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

          pre-commit = {
            check.enable = true;
          };

          packages = {
            inherit (nixpkgs)
              wayfinder-tap
              wayfinder-tui
              wayfinder-ctl
              wayfinder-web
              ;
            wayfinder-simple = nixpkgs.callPackage ./nix/tests/simple.nix { };
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
