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

        nixosModules.default = ./nix/modules/wayfinder-tap.nix;
      };

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          rustToolchain = (
            pkgs.fenix.complete.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
              "llvm-tools-preview"
            ]
          );

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
              rust-analyzer
              pytestEnv
              python312Packages.virtualenv
              socat
              protobuf
              buf
              tshark
              glab
            ];

            nativeBuildInputs = with pkgs; [
              protobuf
            ];

            shellHook = ''
              ${config.pre-commit.installationScript}
              # source .venv/bin/activate

              # pip install --upgrade pip
              # pip install -r training/requirements.txt

              PYTHONPATH=training:$PYTHONPATH
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
            inherit (testPkgs) wayfinder-tap wayfinder-tui wayfinder-ctl;
            wayfinder-simple = testPkgs.callPackage ./nix/tests/simple.nix { };
          };

          treefmt = {
            projectRootFile = "Cargo.toml";
            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              ruff.enable = true;
              buf.enable = true;
              yamlfmt.enable = true;
              dockerfmt.enable = true;
              shellcheck.enable = true;
              stylua.enable = true;
            };
          };
        };
    };
}
