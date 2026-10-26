# Development

Use the pinned flake environment:

```console
nix develop

gofmt -w ./cmd ./internal
go vet ./...
go test -race ./...
nix flake check
```

Keep protocol facts separate from runtime policy. Do not add an unsupported mode, heuristic endian switch, insecure TLS option, unbounded queue, hidden fallback, or gateway-IP special case.

Tests must use synthetic or fully redacted fixtures. Never copy `PASSWD.md`, captures, logs, private keys, session IDs, or authentication tokens from the research directory into this repository or a Nix flake source.
