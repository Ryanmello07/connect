# Custom Network Selection for Miner + Provider Release Workflow Migration — Design

## Context

The provider binary that used to live at `github.com/urnetwork/connect`'s `provider/` directory has been removed from `connect` (upstream commit `3b6b151`, "st: consolidate st integrations into the sn repo", merged into `beta/custom-server` via `774d008` on 2026-07-11). The functional successor now lives in a separate repository, `github.com/urfoundation/sn` (a Bittensor subnet repo), specifically:

- `miner/` — the library implementing what used to be `provider/main.go` (README is verbatim the old provider README).
- `cli/miner/main.go` — thin entry point that calls `miner.Run(os.Args[1:])`.
- `miner/Makefile` — cross-compiles the same GOOS/GOARCH matrix as the old `provider/Makefile`, into `miner/build/miner.tar.gz`, using the same `WARP_VERSION` linker-flag contract.
- `miner/go.mod` (repo root `sn/go.mod`) requires `github.com/urnetwork/connect` and `github.com/urnetwork/glog`, both resolved via local `replace` directives:
  ```
  replace github.com/urnetwork/connect => ../connect
  replace github.com/urnetwork/glog => ../glog
  ```
  This means building `sn/miner` requires `connect` and `glog` checked out as sibling directories to `sn`.

The user does not have push access to `urfoundation/sn` (fork required) and needs a way for miner operators to select a custom network (their own API/connect server) instead of the hardcoded main-network defaults (`https://api.bringyour.com` / `wss://connect.bringyour.com`) baked into `miner/run.go`.

This design covers three sub-projects, each independently shippable:

1. Fork `urfoundation/sn` to `Ryanmello07/sn`.
2. Add a network-selection feature to the forked `miner` package.
3. Update `connect`'s `.github/workflows/provider-release.yml` to build the miner binary from the fork instead of the deleted `provider/` directory.

## Sub-project 1: Fork `urfoundation/sn`

- Fork `urfoundation/sn` → `Ryanmello07/sn` (plain GitHub fork, no content changes).
- Create branch `beta/custom-server` on the fork, off `main`, mirroring the `connect` repo's branch naming convention.
- The fork's `main` branch continues to track `urfoundation/sn`'s `main` for pulling upstream updates. The `beta/custom-server` branch carries the network-selection feature (sub-project 2) and is periodically rebased onto the fork's `main` as upstream changes land.
- No code changes in this sub-project.

## Sub-project 2: Network Selection Feature

**Location:** `Ryanmello07/sn`, `miner` package (`miner/run.go`), on branch `beta/custom-server`.

### New CLI subcommands

Added to the docopt usage string in `mainUsage()` (`miner/run.go`):

```
provider choose_network <api_url> <connect_url>
provider choose_network --reset
```

- `provider choose_network <api_url> <connect_url>`: validates both URLs, then writes them to `~/.urnetwork/network.json`.
- `provider choose_network --reset`: deletes `~/.urnetwork/network.json` if present (no error if absent), reverting all commands to the hardcoded main-network defaults.

### URL validation

- `<api_url>` must parse via `net/url` with scheme `http` or `https`.
- `<connect_url>` must parse via `net/url` with scheme `ws` or `wss`.
- Any other scheme, or a URL that fails to parse, is rejected with a clear error message before anything is written to disk.

### Storage format

`~/.urnetwork/network.json` (alongside the existing `jwt` and `.provider.key` files, using the existing `providerStatePath` helper):

```json
{
  "api_url": "https://example.com",
  "connect_url": "wss://example.com"
}
```

### Resolution order

Applies everywhere `apiUrl`/`connectUrl` are currently resolved from `DefaultApiUrl`/`DefaultConnectUrl` in `miner/run.go` (today at lines ~209, ~331/336, and any other call site following the same `opts.String("--api_url")` / fallback pattern — e.g. `auth`, `provide`, `auth-provide`, `wallet set`, `claim`):

1. `--api_url` / `--connect_url` flags, if passed on that specific invocation — highest precedence, one-off, never persisted.
2. Saved `~/.urnetwork/network.json`, if present.
3. Hardcoded `DefaultApiUrl` / `DefaultConnectUrl` — final fallback (main network).

### New functions (in `miner/run.go`, or a new `miner/network.go` if `run.go` is judged too large to extend further)

```go
// networkConfigPath returns the absolute path of the saved network
// config, alongside jwt and .provider.key under ~/.urnetwork.
func networkConfigPath() (string, error)

// networkConfig is the on-disk shape of ~/.urnetwork/network.json.
type networkConfig struct {
    ApiUrl     string `json:"api_url"`
    ConnectUrl string `json:"connect_url"`
}

// readNetworkConfig loads the saved network config. ok is false (with a
// nil error) when the file does not exist — a fresh install with no
// custom network saved.
func readNetworkConfig() (cfg networkConfig, ok bool, err error)

// writeNetworkConfig validates apiUrl (http/https) and connectUrl
// (ws/wss), then writes them to ~/.urnetwork/network.json, creating
// the ~/.urnetwork directory if needed.
func writeNetworkConfig(apiUrl, connectUrl string) error

// resetNetworkConfig removes ~/.urnetwork/network.json. Removing a
// nonexistent file is not an error.
func resetNetworkConfig() error

// resolveApiUrl implements the 3-tier precedence for the API URL:
// --api_url flag > saved network config > DefaultApiUrl.
func resolveApiUrl(opts docopt.Opts) (string, error)

// resolveConnectUrl implements the 3-tier precedence for the connect
// URL: --connect_url flag > saved network config > DefaultConnectUrl.
func resolveConnectUrl(opts docopt.Opts) (string, error)
```

All existing call sites that currently do:

```go
apiUrl, err := opts.String("--api_url")
if err != nil {
    apiUrl = DefaultApiUrl
}
```

are replaced with:

```go
apiUrl, err := resolveApiUrl(opts)
if err != nil {
    panic(err)
}
```

(and analogously for `connectUrl` / `resolveConnectUrl`). `resolveApiUrl`/`resolveConnectUrl` only return an error for a corrupt/unreadable saved config file — a missing file is not an error and falls through to the next tier.

### New docopt handler

`Run()` gains a branch:

```go
} else if chooseNetwork, _ := opts.Bool("choose_network"); chooseNetwork {
    chooseNetworkCmd(opts)
}
```

`chooseNetworkCmd(opts docopt.Opts)`:
- If `--reset` is set, calls `resetNetworkConfig()`, prints confirmation, returns.
- Otherwise reads `<api_url>` and `<connect_url>` positional args, calls `writeNetworkConfig`, prints confirmation (echoing back the saved values) or the validation error.

### Testing

`miner/run_test.go` (extended) — table-driven tests:

- URL scheme validation: accept `http://`, `https://` for api_url; `ws://`, `wss://` for connect_url; reject `ftp://`, malformed URLs, empty strings.
- Precedence resolution: flag set + no saved config → flag wins; flag unset + saved config present → saved wins; neither present → default wins. Tested independently for api_url and connect_url.
- Reset behavior: `resetNetworkConfig()` on a missing file returns nil; on an existing file removes it and a subsequent `readNetworkConfig()` returns `ok=false`.
- Round-trip: `writeNetworkConfig` followed by `readNetworkConfig` returns the same values.

Tests use `t.Setenv("HOME", t.TempDir())` (or override `providerStatePath` via a test-only indirection if it's not already testable) so they don't touch the real `~/.urnetwork` directory.

## Sub-project 3: Update `connect`'s Release Workflow

**File:** `.github/workflows/provider-release.yml` (existing, modified in place).

### Trigger

- `push` to `beta/custom-server`, paths: `go.mod`, `go.sum` (drop `provider/**` — that path no longer exists in this repo).
- `workflow_dispatch` (unchanged, already present).

### `build` job

Three sibling checkouts, matching `sn/go.mod`'s relative `replace` directives exactly:

1. Check out `Ryanmello07/sn` at `beta/custom-server` into `sn/`.
2. Check out `Ryanmello07/connect` at `beta/custom-server` into `connect/` (sibling of `sn/`, not nested inside it).
3. Check out `urnetwork/glog` at its default branch into `glog/` (sibling of `sn/` and `connect/`).
4. Set up Go using `sn/go.mod`'s version directive (`go-version-file: sn/go.mod`).
5. Compute `short_sha` from the `sn` checkout: `git -C sn rev-parse --short HEAD`.
6. Run `make all` in `sn/miner`, with `WARP_VERSION=beta-custom-server-<short_sha>` (same contract as before).
7. Upload `sn/miner/build/miner.tar.gz` as an artifact named `miner.tar.gz` (renamed from `provider.tar.gz`).

### `release` job

Structurally unchanged from the current workflow:

- Checks out `connect` (needed to force-update the `beta-custom-server-latest` tag).
- Downloads the `miner.tar.gz` artifact.
- Force-updates and pushes the `beta-custom-server-latest` tag.
- Creates/updates the `beta-custom-server-latest` release (prerelease, `make_latest: false`) in `Ryanmello07/connect`, attaching `miner.tar.gz`.
- `contents: write` permission scoped to this job only (unchanged).

### Notes

- If `Ryanmello07/sn`'s `beta/custom-server` branch doesn't exist yet when this workflow is first tested, the checkout step will fail — sub-project 1 must land before sub-project 3 can be verified end-to-end.
- The workflow no longer needs the standalone "Check out glog dependency" step positioned specially; it becomes one of three equivalent sibling checkouts.

## Security Considerations

- No new secrets introduced. All three checkouts use the default `GITHUB_TOKEN` (read access to public repos) or are public reads (`urfoundation/sn`, `urnetwork/glog`).
- `contents: write` remains scoped to the `release` job only.
- The `choose_network` feature only writes to the invoking user's own `~/.urnetwork/network.json` — no network calls are made as part of saving the config; validation is local URL parsing only.

## Out of Scope

- Migrating the release artifact/tag naming away from "provider"/"beta-custom-server" terminology.
- Automatically detecting when `urfoundation/sn` upstream has diverged and needs a rebase — this is a manual, periodic maintenance task for now.
- A `provider network status` command to show the currently active network — can be added later if useful; not requested.
