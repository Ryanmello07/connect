# Connect Provider Release Workflow Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recreate `.github/workflows/provider-release.yml` in `Ryanmello07/connect` so it builds the miner binary from `Ryanmello07/sn`'s `cli/miner` (via `sn/miner/Makefile`) instead of the deleted `connect/provider/`, and publishes it to the existing rolling `beta-custom-server-latest` release.

**Architecture:** A single workflow file, triggered on push to `beta/custom-server` (path-filtered to `go.mod`/`go.sum`) and on `workflow_dispatch`. The `build` job checks out three sibling repos — `sn`, `connect`, `glog` — matching `sn/go.mod`'s relative `replace` directives, builds `sn/miner` via its existing Makefile, and uploads `miner.tar.gz`. The `release` job downloads the artifact and force-updates the `beta-custom-server-latest` release in `connect`.

**Tech Stack:** GitHub Actions, `actions/checkout`, `actions/setup-go`, `actions/upload-artifact`, `actions/download-artifact`, `softprops/action-gh-release`.

## Global Constraints

- Workflow file: `.github/workflows/provider-release.yml` in `/Users/ryanmello/Documents/GitHub/connect` (repo `Ryanmello07/connect`, branch `beta/custom-server`). This file does not currently exist on the branch — create it fresh.
- Trigger: `push` to `beta/custom-server` with `paths: ['go.mod', 'go.sum']`, plus `workflow_dispatch`.
- Three sibling checkouts required, matching `sn/go.mod`'s relative `replace` directives (`replace github.com/urnetwork/connect => ../connect`, `replace github.com/urnetwork/glog => ../glog`):
  - `sn/` ← `Ryanmello07/sn`, branch `beta/custom-server`
  - `connect/` ← `Ryanmello07/connect`, branch `beta/custom-server` (the checkout of this same repo, positioned as a sibling)
  - `glog/` ← `urnetwork/glog`, default branch
- Go version: read from `sn/go.mod` (`go-version-file: sn/go.mod`).
- `WARP_VERSION` format: `beta-custom-server-<short-sha>`, short SHA computed from the `sn` checkout.
- Build command: `make all` in `sn/miner`, producing `sn/miner/build/miner.tar.gz`.
- Artifact name: `miner.tar.gz` (renamed from the old `provider.tar.gz`).
- Release: tag/name `beta-custom-server-latest`, prerelease `true`, `make_latest: false`, force-updates the tag before creating/updating the release, attaches `miner.tar.gz`.
- `contents: write` permission scoped to the `release` job only; default/root permissions `contents: read`.
- No hardcoded secrets; use the automatically provided `GITHUB_TOKEN`.

---

### Task 1: Create the provider release workflow targeting `sn/miner`

**Files:**
- Create: `.github/workflows/provider-release.yml`

**Interfaces:**
- Consumes: `Ryanmello07/sn`'s `beta/custom-server` branch (must exist — created in sub-project 1, already done), `sn/miner/Makefile`'s `all` target, `sn/go.mod`'s `replace` directives.
- Produces: a runnable GitHub Actions workflow, artifact `miner.tar.gz`, GitHub Release `beta-custom-server-latest`.

- [ ] **Step 1: Write the workflow file**

Create `.github/workflows/provider-release.yml`:

```yaml
name: Provider Beta Release

on:
  push:
    branches:
      - beta/custom-server
    paths:
      - 'go.mod'
      - 'go.sum'
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Check out sn
        uses: actions/checkout@v4
        with:
          repository: Ryanmello07/sn
          ref: beta/custom-server
          path: sn

      - name: Check out connect
        uses: actions/checkout@v4
        with:
          repository: Ryanmello07/connect
          ref: beta/custom-server
          path: connect

      - name: Check out glog
        uses: actions/checkout@v4
        with:
          repository: urnetwork/glog
          path: glog

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: 'sn/go.mod'

      - name: Set version
        id: version
        working-directory: sn
        run: echo "short_sha=$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"

      - name: Build miner
        working-directory: sn/miner
        run: make all
        env:
          WARP_VERSION: beta-custom-server-${{ steps.version.outputs.short_sha }}

      - name: Upload miner artifact
        uses: actions/upload-artifact@v4
        with:
          name: miner.tar.gz
          path: sn/miner/build/miner.tar.gz
          if-no-files-found: error

  release:
    runs-on: ubuntu-latest
    needs: build
    permissions:
      contents: write

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Download miner artifact
        uses: actions/download-artifact@v4
        with:
          name: miner.tar.gz

      - name: Update rolling tag
        run: |
          git tag -f beta-custom-server-latest
          git push -f origin beta-custom-server-latest

      - name: Create or update beta release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: beta-custom-server-latest
          name: beta-custom-server-latest
          body: |
            Rolling beta release for the `beta/custom-server` branch, built from
            `Ryanmello07/sn` (miner) at commit ${{ steps.version.outputs.short_sha }}.

            - connect commit: ${{ github.sha }}
            - Timestamp: ${{ github.event.head_commit.timestamp }}
          prerelease: true
          files: miner.tar.gz
          make_latest: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Note: `steps.version.outputs.short_sha` referenced in the release job's body is from the `build` job and is not directly accessible across jobs without `needs.build.outputs`. This is a known limitation — see Step 2 for the fix before finalizing.

- [ ] **Step 2: Fix the cross-job output reference**

`steps.*` outputs are only visible within the same job. To reference the `build` job's short SHA in the `release` job, the `build` job must declare a job-level `outputs` block. Update the workflow: add `outputs` to the `build` job and reference it via `needs.build.outputs` in `release`.

Replace:

```yaml
  build:
    runs-on: ubuntu-latest

    steps:
```

with:

```yaml
  build:
    runs-on: ubuntu-latest
    outputs:
      short_sha: ${{ steps.version.outputs.short_sha }}

    steps:
```

And in the `release` job's `Create or update beta release` step, replace:

```yaml
          body: |
            Rolling beta release for the `beta/custom-server` branch, built from
            `Ryanmello07/sn` (miner) at commit ${{ steps.version.outputs.short_sha }}.
```

with:

```yaml
          body: |
            Rolling beta release for the `beta/custom-server` branch, built from
            `Ryanmello07/sn` (miner) at commit ${{ needs.build.outputs.short_sha }}.
```

- [ ] **Step 3: Validate YAML syntax**

Run: `cd /Users/ryanmello/Documents/GitHub/connect && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/provider-release.yml'))" && echo "YAML OK"`

Expected: prints `YAML OK` with no errors.

- [ ] **Step 4: Verify the referenced branch and Makefile target exist**

Run:

```bash
gh api repos/Ryanmello07/sn/branches/beta/custom-server --jq '.name'
gh api repos/Ryanmello07/sn/contents/miner/Makefile?ref=beta/custom-server --jq '.name'
```

Expected: both commands print a result (`beta/custom-server` and `Makefile` respectively) with no error — confirms the branch and Makefile the workflow depends on exist before the workflow is exercised.

- [ ] **Step 5: Commit**

```bash
cd /Users/ryanmello/Documents/GitHub/connect
git add .github/workflows/provider-release.yml
git commit -m "ci: rebuild provider release workflow to build sn/miner"
```

- [ ] **Step 6: Push the branch**

```bash
cd /Users/ryanmello/Documents/GitHub/connect
git push origin beta/custom-server
```

### Task 2: Trigger and verify the first run against the new source

**Files:**
- None (verification only; no file changes in this task).

**Interfaces:**
- Consumes: the workflow created in Task 1, `Ryanmello07/sn`'s `beta/custom-server` branch (must have the `choose_network` feature commits from the miner-network-selection plan merged in before this task runs, so the build reflects real state — though the workflow itself builds successfully even without those commits, since it only requires `miner/Makefile` and `cli/miner` to exist, which they already do on the freshly forked branch).

- [ ] **Step 1: Manually trigger the workflow**

```bash
gh workflow run provider-release.yml --ref beta/custom-server --repo Ryanmello07/connect
```

Expected: prints a URL like `https://github.com/Ryanmello07/connect/actions/runs/<run-id>` with no error.

- [ ] **Step 2: Watch the run to completion**

```bash
gh run list --repo Ryanmello07/connect --workflow provider-release.yml --limit 1 --json databaseId --jq '.[0].databaseId'
```

Take the printed run ID and run:

```bash
gh run watch <run-id> --repo Ryanmello07/connect
```

Expected: both the `build` and `release` jobs complete with all steps showing ✓, and the command exits with the run's final conclusion printed as success.

- [ ] **Step 3: Verify the release was created/updated**

```bash
gh release view beta-custom-server-latest --repo Ryanmello07/connect --json tagName,assets --jq '{tag: .tagName, assets: [.assets[].name]}'
```

Expected: JSON output showing `"tag": "beta-custom-server-latest"` and `"assets"` containing `"miner.tar.gz"`.

- [ ] **Step 4: If the run failed, capture the failure log before making changes**

```bash
gh run view <run-id> --repo Ryanmello07/connect --log-failed
```

Read the output, identify the failing step, and fix the workflow file accordingly (common issues at this stage: missing branch, Makefile path mismatch, Go version file not found — cross-reference against the Global Constraints section above before altering anything). Re-run Steps 1-3 after any fix, and commit the fix with message `ci: fix <short description>` following the same commit pattern as Task 1 Step 5.

---

## Self-Review

**Spec coverage:**
- Trigger on push to `beta/custom-server`, paths `go.mod`/`go.sum`, plus `workflow_dispatch`: Task 1 Step 1.
- Three sibling checkouts (`sn`, `connect`, `glog`) matching `sn/go.mod`'s replace directives: Task 1 Step 1.
- Go version from `sn/go.mod`: Task 1 Step 1 (`go-version-file: 'sn/go.mod'`).
- `WARP_VERSION=beta-custom-server-<short-sha>` from the `sn` checkout: Task 1 Step 1.
- `make all` in `sn/miner`: Task 1 Step 1.
- Artifact renamed to `miner.tar.gz`: Task 1 Step 1.
- Rolling `beta-custom-server-latest` release, prerelease, tag force-update: Task 1 Step 1.
- `contents: write` scoped to release job only: Task 1 Step 1 (root workflow has no top-level `permissions` key, defaulting to the repository's default, which is `read` for the `GITHUB_TOKEN` on public repos unless configured otherwise — the `release` job explicitly declares `contents: write`, and `build` declares no `permissions` block, so it inherits the default read-only token).
- End-to-end verification: Task 2.

**Placeholder scan:** No TBD/TODO. Task 1 Step 2 explicitly documents and fixes the cross-job output reference issue rather than leaving it as a known bug — this is a real fix, not a placeholder.

**Type consistency:** `steps.version.outputs.short_sha` (job-local) vs. `needs.build.outputs.short_sha` (cross-job) are correctly distinguished between Task 1 Step 1 (initial draft, job-local, correctly scoped to use within the `build` job only) and Step 2's fix (adds the `outputs:` block making `short_sha` available to `release` via `needs.build.outputs.short_sha`). The `env: WARP_VERSION` line in `Build miner` uses `steps.version.outputs.short_sha`, which is correct because that reference is within the same `build` job.
