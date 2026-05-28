{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix.url = "github:numtide/treefmt-nix";

    fenix.url = "github:nix-community/fenix";
  };

  outputs =
    inputs@{
      nixpkgs,
      flake-parts,
      fenix,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;

      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      perSystem =
        {
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
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              fenix.overlays.default
            ];
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              nil
              nixd
              rustToolchain
              cargo-nextest
              cargo-llvm-cov
              rust-analyzer
              python3
              python312Packages.virtualenv
              socat
              protobuf
              buf
            ];

            nativeBuildInputs = with pkgs; [ protobuf ];

            shellHook = ''
              # source .venv/bin/activate

              # pip install --upgrade pip
              # pip install -r training/requirements.txt

              PYTHONPATH=training:$PYTHONPATH
            '';
          };

          treefmt = {
            projectRootFile = "Cargo.toml";
            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              buf.enable = true;
              yamlfmt.enable = true;
            };
          };
        };
    };
}
