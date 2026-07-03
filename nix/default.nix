{ pkgs, src, ... }:
with pkgs.craneLib;
let
  protoFilter = path: type: builtins.match ".*proto$" path != null;
  commonArgs = {
    # We should add more filters here... we only need cargo files, protos, and rust files. No need for nix files.
    src = pkgs.lib.cleanSourceWith {
      inherit src;
      filter = path: type: (filterCargoSources path type) || (protoFilter path type);
      name = "wayfinder-src"; # Be reproducible, regardless of the directory name
    };
    # This is just the name for the workspace pre-build. It will be overwritten by each package;
    pname = "wayfinder-workspace";
    version = "0.1.0";
    nativeBuildInputs = with pkgs; [
      protobuf
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
in
{
  inherit wayfinder-tap wayfinder-tui wayfinder-ctl;
}
