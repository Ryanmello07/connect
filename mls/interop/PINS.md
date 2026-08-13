<!-- connect/mls/interop/PINS.md -->
# Pinned external references

This is the one pin file for the whole slice. Bumping any line here is a pull request that must show
a green interop matrix and a green `vectors` job. Nothing in this file enters `go.mod`.

The two commit lines are machine-readable and are grepped by other plans' tasks; keep the
`key=<40-char sha>` shape exactly.

```
mlswg=cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
openmls=fd2e4891fdd7236f10c596c1f637c5e26c588e5c
```

| What | Pin | Why |
|---|---|---|
| mlswg/mls-implementations | the `mlswg=` line above | the 16 vector families **and** the gRPC test runner, pinned together so the runner and the vectors never disagree |
| openmls/openmls | the `openmls=` line above | the differential oracle and the 9 fuzz targets; built out of process in CI, never linked |
| `ghcr.io/urnetwork/mls-peer-openmls` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mlspp` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mls-rs` | digest `sha256:<...>` | interop peer |

Peer images are prebuilt and pushed to GHCR by the weekly `peer-image-bump` job, which opens a
digest-bump PR. CI never compiles Rust or C++ on a per-commit path.
