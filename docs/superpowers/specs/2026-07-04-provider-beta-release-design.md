# Provider Beta Release Workflow — Design

## Context

The `provider` program is the main Connect provider binary. It lives in the `provider/` directory of the `github.com/urnetwork/connect` repository.

- The Go module is at the repository root (`go 1.26.3`).
- The build is driven by `provider/Makefile`, which cross-compiles for many targets (linux arm64/arm/amd64/386/mips*, darwin arm64/amd64, windows arm64/amd64) and packages them into `provider/build/provider.tar.gz`.
- The program embeds a version via `-ldflags "-X main.Version=${WARP_VERSION}"`.
- There are currently no GitHub Actions workflows in the repository.

## Goal

Create a GitHub Actions workflow that, on every push to the `beta/custom-server` branch, builds the `provider` program and publishes it as a GitHub Release.

## Scope

This is intentionally a minimal, working beta release pipeline. It reuses the existing Makefile and produces a single rolling "latest beta" release.

Out of scope for this iteration:
- Per-binary release artifacts
- Checksums, SBOMs, signing
- Docker image builds
- GoReleaser migration (can be evaluated later)

## Design

### Workflow

- **Path:** `.github/workflows/provider-release.yml`
- **Name:** `Provider Beta Release`

#### Trigger

`push` to `beta/custom-server`, filtered to:
- `provider/**`
- `go.mod`
- `go.sum`

This avoids unnecessary releases when unrelated files change.

#### Jobs

##### 1. build

- **Runner:** `ubuntu-latest`
- **Steps:**
  1. Check out repository at the pushed ref.
  2. Set up Go using the version declared in `go.mod`.
  3. Run `make all` inside the `provider/` directory with:
     - `WARP_VERSION=beta-custom-server-<short-sha>`
     - `GOEXPERIMENT=greenteagc` (already set by the Makefile)
  4. Upload `provider/build/provider.tar.gz` as a workflow artifact.

The version string matches the existing `WARP_VERSION` contract expected by `provider/Makefile`. Example: `beta-custom-server-a1b2c3d`.

##### 2. release

- **Runner:** `ubuntu-latest`
- **Needs:** `build`
- **Permissions:** `contents: write` (scoped to this job only)
- **Steps:**
  1. Download the `provider.tar.gz` artifact.
  2. Create or update a GitHub Release:
     - Tag: `beta-custom-server-latest`
     - Name: `beta-custom-server-latest`
     - Body: short build info including the commit SHA and timestamp
     - Attachment: `provider.tar.gz`
     - Prerelease: `true`
     - If the tag/release already exists, update it in place so the release always points to the latest artifact.

### Release Behavior

Because the workflow targets a beta branch with frequent pushes, it uses a mutable "latest" tag rather than creating a new release for every commit. This keeps the Releases page clean while still making the latest beta build easily available.

The tag will move on each release, which is acceptable for a beta channel.

### Go Version Handling

The workflow reads `go.mod` (e.g. `go 1.26.3`) and passes that value to `actions/setup-go`. This avoids hardcoding a Go version and matches the skill recommendation for Go CI.

## Security Considerations

- The `contents: write` permission is required only for the `release` job, not the `build` job.
- The workflow triggers only on pushes to `beta/custom-server`, not on pull requests.
- No secrets are hardcoded; the release step uses the automatically provided `GITHUB_TOKEN`.

## Future Enhancements

- Add artifact checksums (SHA-256) to the release.
- Attach individual platform binaries alongside `provider.tar.gz`.
- Consider GoReleaser once releases need semver tags, changelogs, or additional package formats.
- Add nightly/test runners (race tests, lint, govulncheck) as separate workflows.
