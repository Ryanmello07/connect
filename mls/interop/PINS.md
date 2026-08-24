<!-- connect/mls/interop/PINS.md -->
# Pinned external references

This is the one pin file for the whole slice. Bumping any line here is a pull request that must show
a green interop matrix and a green `vectors` job. Nothing in this file enters `go.mod`.

The commit lines are machine-readable and are grepped by other plans' tasks; keep the
`key=<40-char sha>` shape exactly.

```
mlswg=cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
openmls=fd2e4891fdd7236f10c596c1f637c5e26c588e5c
hpke=b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb
```

| What | Pin | Why |
|---|---|---|
| mlswg/mls-implementations | the `mlswg=` line above | the 16 vector families **and** the gRPC test runner, pinned together so the runner and the vectors never disagree |
| openmls/openmls | the `openmls=` line above | the differential oracle and the 9 fuzz targets; built out of process in CI, never linked |
| `ghcr.io/urnetwork/mls-peer-openmls` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mlspp` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mls-rs` | digest `sha256:<...>` | interop peer |
| `testdata/vectors/rfc/hpke-rfc9180-x25519.json` | the `hpke=` line above, filtered; sha256 `3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a` | the RFC 9180 base-mode known answers that hold the HPKE instantiation to the RFC rather than to itself; see the section below |

Peer images are prebuilt and pushed to GHCR by the weekly `peer-image-bump` job, which opens a
digest-bump PR. CI never compiles Rust or C++ on a per-commit path.

## testdata/vectors/rfc/hpke-rfc9180-x25519.json

| Field | Value |
|---|---|
| Upstream repository | `cfrg/draft-irtf-cfrg-hpke` |
| Upstream commit | `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb` |
| Upstream path | `test-vectors.json` |
| Upstream sha256 | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` |
| Vendored sha256 | `3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a` |

Fetched from
`https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json`.

Not an mlswg family, hence `rfc/`: `testdata/vectors/*.json` stays exactly the sixteen mlswg files
p8 Task 6 vendors and asserts over.

Filtered from the upstream file by the deterministic selection
`mode == 0 and kem_id == 32 and kdf_id == 1 and aead_id in (1, 3)`, re-serialized with
`json.dumps(out, indent=2, sort_keys=True)` and a trailing newline. That selects exactly the two
HPKE instantiations the two registered MLS ciphersuites use. Nothing is truncated: both entries
carry all 257 encryptions and all 3 exports.

The full upstream file is 5.9 MB and 128 entries, of which 126 are for algorithms this
implementation does not have and will never gain, so vendoring it whole would be 5.7 MB of
permanently dead weight in every clone.

Because the vendored file is a re-serialization rather than a copy, the byte-for-byte comparison
against upstream that every other row here gets is made against the upstream file's own digest
above, and the transform is held to it separately: the two vendored entries were asserted to
deep-equal the two upstream entries the predicate selects, and re-running the transform was
asserted to reproduce the vendored bytes exactly. Re-vendoring is therefore reproducible from the
upstream commit and this paragraph alone.

`core.autocrlf` is `true` at system scope on at least one machine that writes to this repository,
and the sixteen mlswg files were once vendored already smudged with a manifest computed over the
smudged bytes, so they verified against bytes upstream never published.
`testdata/vectors/rfc/.gitattributes` carries `* -text` and was committed before the file it
protects; `git ls-files --eol` reports `i/lf w/lf attr/-text`, and
`TestHpkeVectorFileCarriesTheBytesUpstreamPublished` refuses a carriage return in the file at all.

The vendored digest is pinned a second time in `mls/hpke_vectors_test.go` as `hpkeVectorSha256`,
and `TestHpkeVectorDigestIsRecordedInThePinFile` asserts this file and that constant agree, so the
two cannot drift apart.
