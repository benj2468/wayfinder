{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    inputs@{ nixpkgs, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;

      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      perSystem =
        {
          pkgs,
          ...
        }:
        {

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              nil
              nixd
              cargo
              clippy
              cargo-nextest
              rustc
              rust-analyzer
              rustfmt
              python3
              python312Packages.virtualenv
              socat
              protobuf
              buf
            ];

            nativeBuildInputs = with pkgs; [ protobuf ];

            RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;

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
