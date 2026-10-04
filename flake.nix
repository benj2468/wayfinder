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
      # What a Nix-built binary reports as its build identity.
      #
      # It has to come from here: `.git` reaches no Nix build — a flake's store
      # source excludes it, `lib.cleanSource` filters it, and crane's
      # `filterCargoSources` keeps only Rust/Cargo files — so
      # `wayfinder-version`'s build script has nothing to ask. Flake metadata
      # knows the answer exactly, which is the point: a release build's version
      # is not a guess.
      #
      # `shortRev` is absent for a dirty tree and `dirtyShortRev` for a clean
      # one, so both are tried; `null` falls through to whatever the build script
      # can work out for itself (a `nix build` outside a git tree reports
      # "unknown" rather than failing).
      #
      # Two couplings worth stating, because both are invisible from the Rust
      # side:
      #
      #  - The *dirty* marker survives only because `dirtyShortRev` is formatted
      #    `<rev>-dirty` and the resolver reads the suffix off the string.
      #    Nothing injects a separate dirty flag.
      #  - Nix calls a tree dirty when it holds *untracked* files, while the
      #    `BuildInfo.dirty` field promises "untracked files do not count" (which
      #    is true of the git tier, `git describe --dirty`). A stray scratch file
      #    therefore makes a Nix build report a modified tree where a plain
      #    `cargo build` of the same commit would not. `source` is on the wire so
      #    a reader can tell which rule produced the answer.
      buildVersion = inputs.self.dirtyShortRev or inputs.self.shortRev or null;

      # The commit, passed separately because `buildVersion` above may be a bare
      # revision with no other identity in it — and, once a release-tag
      # convention exists, may be a tag with no hash at all. Without this every
      # Nix-built node (the cloud CA, the Orin, every spoke) reports
      # `commit: "unknown"`, which is exactly the question this feature exists to
      # answer.
      #
      # Two normalisations, both needed: `dirtyRev` is the full revision with
      # `-dirty` *appended*, which does not belong in a field whose only job is to
      # name a commit (the version string beside it already carries dirtiness),
      # and the git tier abbreviates to 7 so this matches rather than reporting 40
      # characters for the same field on a different node.
      buildCommit =
        let
          rev = inputs.self.rev or inputs.self.dirtyRev or null;
        in
        if rev == null then null else builtins.substring 0 7 rev;

      # The overlay, parameterised on the build identity it stamps into the
      # binaries. See `overlay` and `unstampedOverlay` below for the two uses.
      mkOverlay =
        { buildVersion, buildCommit }:
        final: prev: {
          craneLib = inputs.crane.mkLib prev;

          cudaPackages = final.cudaPackages_13_0;

          inherit
            (prev.callPackage ./nix {
              src = prev.lib.cleanSource ./.;
              inherit buildVersion buildCommit;
            })
            wayfinder-tap
            wayfinder-tui
            wayfinder-ctl
            wayfinder-web
            wayfinder-shark
            wayfinder-tshark
            wayfinder-termshark
            ;
        };

      # What every deployment and every published package is built with: the
      # commit stamped on, so a running node can say which build it is. The
      # stamp is a wrapper over the unstamped compile (`stamp` in
      # `nix/default.nix`), so these come from CI's cache whenever the Rust
      # sources match a build it has made.
      overlay = mkOverlay { inherit buildVersion buildCommit; };

      # The same packages with no build identity, for what CI builds: the NixOS
      # tests. These are the compiled derivations the stamped packages wrap, so
      # CI's build of them is what a deployment substitutes. Without the
      # wrapper, the test closure changes only when the filtered Rust/proto/web
      # source does, and a test result stays cached across commits that leave
      # it alone. No test asserts on the version; the binaries report
      # "unknown".
      unstampedOverlay = mkOverlay {
        buildVersion = null;
        buildCommit = null;
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

      # A cloud instance, which needs none of `mkWayfinderSystem`'s installer
      # half. That builder exists for a *board*: it pairs the system with a
      # live USB image carrying the disk layout and the built closure, so a
      # board with no network can be installed from the stick. A cloud VM is
      # installed by `nixos-anywhere` kexec-ing over whatever stock image the
      # provider booted — there is no stick, and the machine has a network by
      # definition. So this yields the one configuration and nothing else.
      #
      # It still shares `common.nix`/`system.nix`/`disk.nix` + disko with the
      # board path, so the two stay the same shape on disk.
      mkCloudSystem =
        name:
        {
          modules ? [ ],
        }:
        let
          dir = ./nix/machines + "/${name}";
        in
        {
          ${name} = nixpkgs.lib.nixosSystem {
            specialArgs = { inherit inputs; };
            modules = [
              {
                nixpkgs = {
                  overlays = [
                    fenix.overlays.default
                    overlay
                  ];
                  config.allowUnfree = true;
                };
              }
              inputs.disko.nixosModules.disko
              (dir + "/common.nix")
              (dir + "/system.nix")
              (dir + "/disk.nix")
            ]
            ++ modules;
          };
        };

      mkCloudSystems =
        machines: nixpkgs.lib.mergeAttrsList (nixpkgs.lib.mapAttrsToList mkCloudSystem machines);
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
        nixosConfigurations =
          mkWayfinderSystems {
            orin-nano.modules = [ jetpack.nixosModules.default ];
          }
          # Cloud instances, which have no installer image — see `mkCloudSystem`.
          # `wayfinder-ca` is the mesh certificate authority; `infra/oracle/`
          # provisions the instance it is installed onto.
          // mkCloudSystems {
            wayfinder-ca.modules = [ ];
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
          # Bare-metal target for the embedded (`no_std`) crates with an FPU —
          # the nRF52840 and STM32F411 (both Cortex-M4F), and what
          # `libs/nrf-ieee802154` builds against. Combined (not
          # `withComponents`-ed) onto the host toolchain below so `cargo build
          # --target thumbv7em-none-eabihf` picks up its prebuilt
          # `core`/`alloc` without needing nightly's `-Z build-std`.
          bareMetalTarget = "thumbv7em-none-eabihf";

          # The **soft-float** sibling, for `bins/wayfinder-wl55jc`. The
          # STM32WL55's Cortex-M4 has no FPU, so it is a genuinely different
          # target and not a variant of the one above — building that board
          # against `eabihf` yields an image that links and then HardFaults on
          # its first float. Both `embassy-stm32` and `stm32-metapac` map
          # `stm32wl.*` to this triple.
          bareMetalSoftFloatTarget = "thumbv7em-none-eabi";

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
            pkgs.fenix.targets.${bareMetalSoftFloatTarget}.latest.rust-std
            pkgs.fenix.targets.${wasmTarget}.latest.rust-std
          ];

          # Python interpreter with the integration-test deps (pytest). Used by
          # both the default dev shell and the lightweight `pytest` shell that
          # CI runs — see tests/README.md and .github/workflows/ci.yml.
          pytestEnv = pkgs.python3.withPackages (ps: with ps; [ pytest ]);

          nixpkgs = nixpkgsForSystem system;

          # See `unstampedOverlay`. Applied on top rather than as a second
          # import, so it reuses this nixpkgs' config and only re-binds the
          # wayfinder packages.
          nixpkgsUnstamped = nixpkgs.extend unstampedOverlay;

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

          # The ESP32 is the one board target Nix cannot hand us a compiler
          # for. Xtensa has no upstream LLVM backend, so there is no
          # `xtensa-esp32-none-elf` in `rustc --print target-list` and no
          # `fenix.targets.<...>.rust-std` to combine into `rustToolchain`
          # above — the compiler is Espressif's own rustc fork, published as a
          # prebuilt tarball and installed by `espup`. (The RISC-V ESP32s —
          # C3/C6/H2 — need none of this; `riscv32imc-unknown-none-elf` is an
          # upstream target fenix serves like any other. This whole section
          # exists for the Xtensa parts: the original ESP32, the S2 and S3.)
          #
          # So this is a deliberately *impure* corner of an otherwise hermetic
          # shell: the shell provides `espup` and the plumbing it needs, and
          # the toolchain itself lands in `$HOME` on first `just esp-toolchain`
          # rather than in the store. Three things have to be arranged for that
          # to work here, none of them obvious from espup's own docs:
          #
          #  * **`rustup` must exist but must not be on PATH.** espup unpacks
          #    the fork into rustup's toolchain directory
          #    (`$RUSTUP_HOME/toolchains/esp`) and shells out to `rustup
          #    toolchain install` for the stable/RISC-V half, so it refuses to
          #    run without it. But rustup's `cargo`/`rustc` are *proxies*, and
          #    on PATH they would shadow the fenix toolchain with shims that
          #    resolve no default toolchain — breaking every ordinary host
          #    build in the shell. Hence a wrapper with rustup as a runtime
          #    input, rather than `rustup` in `packages`.
          #  * **What espup unpacks is an FHS binary**, which does not run on
          #    NixOS as-is. `nix-ld` covers it, given the libraries the fork's
          #    rustc and the Xtensa LLVM need — wired up in the shellHook via
          #    `NIX_LD_LIBRARY_PATH`.
          #  * **`cargo +esp` is a rustup feature**, unavailable for the reason
          #    above, so a build against the fork calls that toolchain's own
          #    `cargo` directly — `esp-env`/`esp-cargo` below are that call.
          #
          # If this ever needs to run in CI, the replacement is a derivation
          # fetching the same `esp-rs/rust-build` release through
          # `autoPatchelfHook` — pure, cacheable, and a pinned hash to bump.
          espupWrapped = pkgs.writeShellApplication {
            name = "espup";
            runtimeInputs = [ pkgs.rustup ];
            text = ''
              exec ${pkgs.espup}/bin/espup "$@"
            '';
          };

          # Runs one command inside the Xtensa toolchain's environment: the
          # fork's own `bin/` ahead of the fenix toolchain on PATH, plus
          # whatever espup's export file describes — `xtensa-esp-elf-gcc` (the
          # linker rustc drives for `xtensa-esp32-none-elf`) and
          # `LIBCLANG_PATH` for the bindgen in an `esp-idf-sys`-style `std`
          # build.
          #
          # `esp-env <cmd>` rather than one wrapper per tool because the
          # interesting commands are not all `cargo`: `rustc --print
          # target-list` is how you confirm the fork is the fork, and the GCC
          # is worth being able to invoke directly when a link fails. Shadowing
          # PATH inside the wrapper keeps that scoped to the one command — an
          # ordinary `cargo build` in this shell still means the host
          # toolchain.
          #
          # It reports a missing install as a directed error, because the
          # alternative is an unrecognisable `No such file or directory` from
          # `exec`.
          espEnv = pkgs.writeShellApplication {
            name = "esp-env";
            text = ''
              rustup_home="''${RUSTUP_HOME:-$HOME/.rustup}"
              toolchain="$rustup_home/toolchains/''${ESP_TOOLCHAIN_NAME:-esp}"

              if [ ! -x "$toolchain/bin/rustc" ]; then
                echo "esp-env: no Xtensa toolchain at $toolchain" >&2
                echo "esp-env: install it with 'just esp-toolchain'" >&2
                exit 1
              fi

              export_file="''${ESPUP_EXPORT_FILE:-$HOME/.espup/export-esp.sh}"
              if [ -f "$export_file" ]; then
                # shellcheck disable=SC1090 # generated by espup at install time
                . "$export_file"
              fi

              export PATH="$toolchain/bin:$PATH"
              exec "$@"
            '';
          };

          # The common case, spelled the way `cargo +esp build` would be if
          # rustup were on PATH.
          espCargo = pkgs.writeShellApplication {
            name = "esp-cargo";
            runtimeInputs = [ espEnv ];
            text = ''
              exec esp-env cargo "$@"
            '';
          };

        in
        {
          _module.args.pkgs = nixpkgs;

          pre-commit.settings.hooks.treefmt.enable = true;

          devShells.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
            packages =
              let
                onlyLinuxPkgs = with pkgs; [
                  probe-rs-tools
                  flip-link
                  nrfutil.withAllExtensions
                  nrf5-sdk
                  nrf-command-line-tools
                  nrfutilNrf5sdkTools
                ];
              in
              with pkgs;
              [
                nil
                nixd
                rustToolchain
                cargo-nextest
                cargo-machete
                cargo-bloat
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
                gh
                just
                stdenv.cc.cc.lib
                # Cloud deployment (`infra/oracle/`, `nix/machines/wayfinder-ca`):
                # OpenTofu provisions the instance, `nixos-anywhere` installs
                # NixOS over the stock image the provider booted.
                opentofu
                nixos-anywhere
                # The wayfndr.dev landing page (`www/`) has no build step, but
                # its deploy does: `wrangler pages deploy` is npm-distributed,
                # and `prettier` is what treefmt formats the page with. Node is
                # here for those two and nothing else — the site itself ships
                # no JavaScript toolchain.
                nodejs_22
                # ESP32 (Xtensa) toolchain management and flashing — see the
                # `espupWrapped` comment above for why the compiler itself
                # isn't a Nix package. `espflash` replaces `probe-rs` for
                # these boards: an ESP32 ships with a serial bootloader in
                # ROM, so the usual bring-up needs a USB cable rather than a
                # debug probe. `ldproxy` is the linker shim `esp-idf-sys`
                # builds invoke; harmless for `no_std` and needed the moment a
                # `std` (ESP-IDF) build is tried. `esp-generate` scaffolds a
                # board crate, which is how `bins/wayfinder-esp32` starts.
                espupWrapped
                espEnv
                espCargo
                espflash
                ldproxy
                esp-generate
              ]
              ++ (pkgs.lib.optionals pkgs.stdenv.isLinux onlyLinuxPkgs);

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

              # Where espup writes the environment its toolchain needs, and
              # where `esp-env` reads it back from. espup's own default is
              # `$HOME/export-esp.sh`, i.e. loose in the home directory;
              # pinning it into the directory espup already owns keeps one
              # variable as the single answer for both halves. (espup 0.17 keeps
              # the GCC and Xtensa LLVM *inside* the toolchain directory and
              # symlinks the clang libs into `~/.espup`, so there is no
              # `~/.espressif` here despite what older esp-rs docs describe.)
              export ESPUP_EXPORT_FILE="$HOME/.espup/export-esp.sh"

              # The Xtensa toolchain espup installs is a stock FHS build (see
              # `espupWrapped` above), so on NixOS its rustc, its LLVM libs and
              # `xtensa-esp-elf-gcc` reach for an interpreter and shared
              # libraries that do not exist at those paths. `nix-ld` answers
              # the interpreter; this answers the libraries. Appended rather
              # than assigned, so a system-wide `programs.nix-ld.libraries`
              # keeps whatever it already put there, and `NIX_LD` is filled in
              # only if unset — on a non-NixOS host the real loader is already
              # at the path the binaries name and nothing here applies.
              export NIX_LD="''${NIX_LD:-${pkgs.stdenv.cc.bintools.dynamicLinker}}"
              export NIX_LD_LIBRARY_PATH="${
                pkgs.lib.makeLibraryPath [
                  pkgs.stdenv.cc.cc.lib
                  pkgs.zlib
                  pkgs.libxml2
                  pkgs.ncurses
                  pkgs.openssl
                ]
              }''${NIX_LD_LIBRARY_PATH:+:''${NIX_LD_LIBRARY_PATH}}"

              export PATH=/run/wrappers/bin:$PATH
              ${pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
                # The `rust-lld` fenix ships for darwin is linked against
                # `@rpath/libLLVM.dylib`, but its only usable `LC_RPATH` is
                # `@loader_path/../lib` — and the binary lives in
                # `lib/rustlib/aarch64-apple-darwin/bin/`, so that resolves to a
                # directory the library is not in. It sits one level up, in the
                # toolchain's own `lib/`. Nothing on the host build path notices
                # (Apple's `cc` links those), but `wasm32-unknown-unknown` uses
                # `rust-lld` directly, so `bins/wayfinder-web`'s hydration half
                # dies at link time with `dyld: Library not loaded`. Point the
                # fallback search there; the trailing entries are dyld's own
                # defaults, which setting this variable would otherwise replace.
                export DYLD_FALLBACK_LIBRARY_PATH="${rustToolchain}/lib:$HOME/lib:/usr/local/lib:/usr/lib"
              ''}
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
              wayfinder-shark
              wayfinder-tshark
              wayfinder-termshark
              ;
            wayfinder-simple = nixpkgsUnstamped.callPackage ./nix/tests/simple.nix { };
            wayfinder-ethernet-egress = nixpkgsUnstamped.callPackage ./nix/tests/ethernet-egress.nix { };
            # The cloud certificate-authority posture: no local egress, no
            # links, provider mode, unprivileged. Covers what
            # `nix/machines/wayfinder-ca` deploys, without a cloud account.
            wayfinder-ca-provider = nixpkgsUnstamped.callPackage ./nix/tests/ca-provider.nix { };
            # The VPN data plane: real mesh traffic over a real Tailscale
            # tunnel between two nodes with no other path to each other. See
            # docs/design/implemented/08-internet-links-headscale-vpn.md's own
            # stated gap.
            wayfinder-vpn-data-plane = nixpkgsUnstamped.callPackage ./nix/tests/vpn-data-plane.nix { };
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
              # Scoped to `www/` below. Left unscoped, prettier's default
              # includes sweep in every Markdown, YAML and JSON file in the
              # repo and reformat them, which is a large unrelated diff and
              # would fight `yamlfmt` over the YAML.
              prettier.enable = true;
            };

            settings.formatter.prettier.includes = pkgs.lib.mkForce [
              "www/*.html"
              "www/*.css"
              "www/*.js"
            ];

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
