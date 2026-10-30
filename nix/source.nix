{ lib }:

lib.fileset.toSource {
  root = ../.;
  fileset = lib.fileset.unions [
    ../cmd
    ../internal
    ../docs/config.example.json
    ../go.mod
    ../go.sum
  ];
}
