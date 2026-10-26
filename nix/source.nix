{ lib }:

lib.fileset.toSource {
  root = ../.;
  fileset = lib.fileset.unions [
    ../cmd
    ../internal
    ../go.mod
    ../go.sum
  ];
}
