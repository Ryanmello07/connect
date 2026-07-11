# Miner Network Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let miner operators choose a custom network (API + connect URLs) via `provider choose_network`, persisted to `~/.urnetwork/network.json`, with `--api_url`/`--connect_url` flags still overriding per-run, and a `--reset` option to revert to the main network.

**Architecture:** A new `miner/network.go` file owns config file I/O and URL validation. `miner/run.go` gains a `choose_network` docopt subcommand and two resolver functions (`resolveApiUrl`, `resolveConnectUrl`) that replace the four existing inline `apiUrl = DefaultApiUrl` / `connectUrl = DefaultConnectUrl` fallback blocks across `miner/run.go` and `miner/sn.go`.

**Tech Stack:** Go 1.26, `github.com/docopt/docopt-go`, standard library (`net/url`, `encoding/json`, `os`).

## Global Constraints

- Repo: `/Users/ryanmello/Documents/GitHub/sn`, branch `beta/custom-server`.
- Config file: `~/.urnetwork/network.json`, resolved via the existing `providerStatePath` helper in `miner/run.go`.
- `<api_url>` must have scheme `http` or `https`; `<connect_url>` must have scheme `ws` or `wss`. Reject anything else with a clear error before writing.
- Resolution order for both URLs: `--api_url`/`--connect_url` flag (if passed) > saved `network.json` (if present) > hardcoded `DefaultApiUrl`/`DefaultConnectUrl`.
- `provider choose_network --reset` deletes `~/.urnetwork/network.json`; deleting a nonexistent file is not an error.
- All 4 existing call sites using the `opts.String("--api_url")` / `DefaultApiUrl` fallback pattern must be migrated: `miner/run.go` `auth()` (currently lines 207-210), `miner/run.go` `provide()` (currently lines 329-336), `miner/sn.go` `walletSet()` (currently lines 94-97), `miner/sn.go` `claim()` (currently lines 133-136).
- No new external dependencies.

---

### Task 1: Network config file I/O and URL validation

**Files:**
- Create: `miner/network.go`
- Test: `miner/network_test.go`

**Interfaces:**
- Consumes: `providerStatePath(name string) (string, error)` — already defined in `miner/run.go:582`, resolves to `~/.urnetwork/<name>`.
- Produces:
  - `type networkConfig struct { ApiUrl string; ConnectUrl string }` (JSON tags `api_url`, `connect_url`)
  - `func networkConfigPath() (string, error)`
  - `func validateApiUrl(rawUrl string) error`
  - `func validateConnectUrl(rawUrl string) error`
  - `func readNetworkConfig() (cfg networkConfig, ok bool, err error)`
  - `func writeNetworkConfig(apiUrl, connectUrl string) error`
  - `func resetNetworkConfig() error`

- [ ] **Step 1: Write the failing tests**

Create `miner/network_test.go`:

```go
package miner

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestValidateApiUrl(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com", false},
		{"http://example.com", false},
		{"ws://example.com", true},
		{"wss://example.com", true},
		{"ftp://example.com", true},
		{"not a url", true},
		{"", true},
	}
	for _, c := range cases {
		err := validateApiUrl(c.url)
		if c.wantErr && err == nil {
			t.Errorf("validateApiUrl(%q): expected error, got nil", c.url)
		}
		if !c.wantErr && err != nil {
			t.Errorf("validateApiUrl(%q): unexpected error: %s", c.url, err)
		}
	}
}

func TestValidateConnectUrl(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"ws://example.com", false},
		{"wss://example.com", false},
		{"http://example.com", true},
		{"https://example.com", true},
		{"ftp://example.com", true},
		{"not a url", true},
		{"", true},
	}
	for _, c := range cases {
		err := validateConnectUrl(c.url)
		if c.wantErr && err == nil {
			t.Errorf("validateConnectUrl(%q): expected error, got nil", c.url)
		}
		if !c.wantErr && err != nil {
			t.Errorf("validateConnectUrl(%q): unexpected error: %s", c.url, err)
		}
	}
}

func TestReadNetworkConfigMissing(t *testing.T) {
	withTempHome(t)
	_, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("readNetworkConfig: expected ok=false for missing file")
	}
}

func TestWriteThenReadNetworkConfig(t *testing.T) {
	withTempHome(t)
	if err := writeNetworkConfig("https://example.com", "wss://example.com"); err != nil {
		t.Fatalf("writeNetworkConfig: unexpected error: %s", err)
	}
	cfg, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if !ok {
		t.Fatalf("readNetworkConfig: expected ok=true after write")
	}
	if cfg.ApiUrl != "https://example.com" {
		t.Errorf("ApiUrl = %q, want %q", cfg.ApiUrl, "https://example.com")
	}
	if cfg.ConnectUrl != "wss://example.com" {
		t.Errorf("ConnectUrl = %q, want %q", cfg.ConnectUrl, "wss://example.com")
	}
}

func TestWriteNetworkConfigRejectsBadUrls(t *testing.T) {
	withTempHome(t)
	if err := writeNetworkConfig("ws://example.com", "wss://example.com"); err == nil {
		t.Fatalf("writeNetworkConfig: expected error for bad api_url scheme")
	}
	if err := writeNetworkConfig("https://example.com", "https://example.com"); err == nil {
		t.Fatalf("writeNetworkConfig: expected error for bad connect_url scheme")
	}
	// Nothing should have been written.
	_, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("readNetworkConfig: expected ok=false after rejected write")
	}
}

func TestResetNetworkConfig(t *testing.T) {
	withTempHome(t)

	// Reset on a missing file is a no-op, not an error.
	if err := resetNetworkConfig(); err != nil {
		t.Fatalf("resetNetworkConfig on missing file: unexpected error: %s", err)
	}

	if err := writeNetworkConfig("https://example.com", "wss://example.com"); err != nil {
		t.Fatalf("writeNetworkConfig: unexpected error: %s", err)
	}
	if err := resetNetworkConfig(); err != nil {
		t.Fatalf("resetNetworkConfig: unexpected error: %s", err)
	}
	_, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("readNetworkConfig: expected ok=false after reset")
	}
}

func TestNetworkConfigPath(t *testing.T) {
	home := withTempHome(t)
	p, err := networkConfigPath()
	if err != nil {
		t.Fatalf("networkConfigPath: unexpected error: %s", err)
	}
	want := filepath.Join(home, ".urnetwork", "network.json")
	if p != want {
		t.Errorf("networkConfigPath = %q, want %q", p, want)
	}
	// Path resolution must not require the file or directory to exist.
	if _, err := os.Stat(filepath.Dir(p)); err == nil {
		t.Fatalf("expected ~/.urnetwork to not exist yet before any write")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestValidateApiUrl|TestValidateConnectUrl|TestReadNetworkConfigMissing|TestWriteThenReadNetworkConfig|TestWriteNetworkConfigRejectsBadUrls|TestResetNetworkConfig|TestNetworkConfigPath' -v`

Expected: FAIL — compile error, `validateApiUrl`, `validateConnectUrl`, `readNetworkConfig`, `writeNetworkConfig`, `resetNetworkConfig`, `networkConfigPath` are undefined.

- [ ] **Step 3: Write the implementation**

Create `miner/network.go`:

```go
package miner

// network.go — persisted custom-network selection for the miner CLI.
// `provider choose_network <api_url> <connect_url>` writes the chosen
// network to ~/.urnetwork/network.json (alongside jwt and
// .provider.key, via the existing providerStatePath helper);
// `provider choose_network --reset` removes it. resolveApiUrl and
// resolveConnectUrl (in run.go) apply the flag > saved-config > default
// precedence on top of this file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// networkConfig is the on-disk shape of ~/.urnetwork/network.json.
type networkConfig struct {
	ApiUrl     string `json:"api_url"`
	ConnectUrl string `json:"connect_url"`
}

// networkConfigPath returns the absolute path of the saved network
// config, alongside jwt and .provider.key under ~/.urnetwork. Does not
// require the file or the ~/.urnetwork directory to exist.
func networkConfigPath() (string, error) {
	return providerStatePath("network.json")
}

// validateApiUrl requires an http or https URL.
func validateApiUrl(rawUrl string) error {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return fmt.Errorf("invalid api_url %q: %w", rawUrl, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid api_url %q: scheme must be http or https, got %q", rawUrl, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid api_url %q: missing host", rawUrl)
	}
	return nil
}

// validateConnectUrl requires a ws or wss URL.
func validateConnectUrl(rawUrl string) error {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return fmt.Errorf("invalid connect_url %q: %w", rawUrl, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("invalid connect_url %q: scheme must be ws or wss, got %q", rawUrl, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid connect_url %q: missing host", rawUrl)
	}
	return nil
}

// readNetworkConfig loads the saved network config. ok is false (with a
// nil error) when the file does not exist — a fresh install with no
// custom network saved.
func readNetworkConfig() (cfg networkConfig, ok bool, err error) {
	p, err := networkConfigPath()
	if err != nil {
		return networkConfig{}, false, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return networkConfig{}, false, nil
	}
	if err != nil {
		return networkConfig{}, false, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return networkConfig{}, false, fmt.Errorf("parse %s: %w", p, err)
	}
	return cfg, true, nil
}

// writeNetworkConfig validates apiUrl (http/https) and connectUrl
// (ws/wss), then writes them to ~/.urnetwork/network.json, creating the
// ~/.urnetwork directory if needed. Nothing is written if validation
// fails.
func writeNetworkConfig(apiUrl, connectUrl string) error {
	if err := validateApiUrl(apiUrl); err != nil {
		return err
	}
	if err := validateConnectUrl(connectUrl); err != nil {
		return err
	}
	p, err := networkConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(networkConfig{ApiUrl: apiUrl, ConnectUrl: connectUrl}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0600)
}

// resetNetworkConfig removes ~/.urnetwork/network.json. Removing a
// nonexistent file is not an error.
func resetNetworkConfig() error {
	p, err := networkConfigPath()
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestValidateApiUrl|TestValidateConnectUrl|TestReadNetworkConfigMissing|TestWriteThenReadNetworkConfig|TestWriteNetworkConfigRejectsBadUrls|TestResetNetworkConfig|TestNetworkConfigPath' -v`

Expected: PASS (all 7 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/ryanmello/Documents/GitHub/sn
git add miner/network.go miner/network_test.go
git commit -m "feat(miner): add persisted network config with URL validation"
```

---

### Task 2: Resolver functions and call-site migration

**Files:**
- Modify: `miner/run.go:207-210` (in `auth()`), `miner/run.go:329-336` (in `provide()`)
- Modify: `miner/sn.go:94-97` (in `walletSet()`), `miner/sn.go:133-136` (in `claim()`)
- Test: `miner/network_test.go` (append)

**Interfaces:**
- Consumes: `networkConfig`, `readNetworkConfig() (networkConfig, bool, error)` from Task 1.
- Produces:
  - `func resolveApiUrl(opts docopt.Opts) (string, error)`
  - `func resolveConnectUrl(opts docopt.Opts) (string, error)`

- [ ] **Step 1: Write the failing tests**

Append to `miner/network_test.go`:

```go
func TestResolveApiUrlPrecedence(t *testing.T) {
	withTempHome(t)

	// Neither flag nor saved config: falls back to DefaultApiUrl.
	opts := parseArgsForTest(t, []string{"provide"})
	got, err := resolveApiUrl(opts)
	if err != nil {
		t.Fatalf("resolveApiUrl: unexpected error: %s", err)
	}
	if got != DefaultApiUrl {
		t.Errorf("resolveApiUrl (no flag, no saved) = %q, want %q", got, DefaultApiUrl)
	}

	// Saved config present, no flag: saved config wins.
	if err := writeNetworkConfig("https://saved.example.com", "wss://saved.example.com"); err != nil {
		t.Fatalf("writeNetworkConfig: unexpected error: %s", err)
	}
	got, err = resolveApiUrl(opts)
	if err != nil {
		t.Fatalf("resolveApiUrl: unexpected error: %s", err)
	}
	if got != "https://saved.example.com" {
		t.Errorf("resolveApiUrl (saved, no flag) = %q, want %q", got, "https://saved.example.com")
	}

	// Flag present: flag wins over saved config.
	flagOpts := parseArgsForTest(t, []string{"provide", "--api_url=https://flag.example.com"})
	got, err = resolveApiUrl(flagOpts)
	if err != nil {
		t.Fatalf("resolveApiUrl: unexpected error: %s", err)
	}
	if got != "https://flag.example.com" {
		t.Errorf("resolveApiUrl (flag) = %q, want %q", got, "https://flag.example.com")
	}
}

func TestResolveConnectUrlPrecedence(t *testing.T) {
	withTempHome(t)

	opts := parseArgsForTest(t, []string{"provide"})
	got, err := resolveConnectUrl(opts)
	if err != nil {
		t.Fatalf("resolveConnectUrl: unexpected error: %s", err)
	}
	if got != DefaultConnectUrl {
		t.Errorf("resolveConnectUrl (no flag, no saved) = %q, want %q", got, DefaultConnectUrl)
	}

	if err := writeNetworkConfig("https://saved.example.com", "wss://saved.example.com"); err != nil {
		t.Fatalf("writeNetworkConfig: unexpected error: %s", err)
	}
	got, err = resolveConnectUrl(opts)
	if err != nil {
		t.Fatalf("resolveConnectUrl: unexpected error: %s", err)
	}
	if got != "wss://saved.example.com" {
		t.Errorf("resolveConnectUrl (saved, no flag) = %q, want %q", got, "wss://saved.example.com")
	}

	flagOpts := parseArgsForTest(t, []string{"provide", "--connect_url=wss://flag.example.com"})
	got, err = resolveConnectUrl(flagOpts)
	if err != nil {
		t.Fatalf("resolveConnectUrl: unexpected error: %s", err)
	}
	if got != "wss://flag.example.com" {
		t.Errorf("resolveConnectUrl (flag) = %q, want %q", got, "wss://flag.example.com")
	}
}
```

Note: `parseArgsForTest` is already defined in `miner/main_test.go` and is available to this test file since both are in package `miner`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestResolveApiUrlPrecedence|TestResolveConnectUrlPrecedence' -v`

Expected: FAIL — compile error, `resolveApiUrl` and `resolveConnectUrl` are undefined.

- [ ] **Step 3: Add resolver functions to `miner/network.go`**

Append to `miner/network.go` (add `"github.com/docopt/docopt-go"` to the import block):

```go
import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/docopt/docopt-go"
)
```

```go
// resolveApiUrl implements the 3-tier precedence for the API URL:
// --api_url flag > saved network config > DefaultApiUrl.
func resolveApiUrl(opts docopt.Opts) (string, error) {
	if apiUrl, err := opts.String("--api_url"); err == nil {
		return apiUrl, nil
	}
	cfg, ok, err := readNetworkConfig()
	if err != nil {
		return "", err
	}
	if ok {
		return cfg.ApiUrl, nil
	}
	return DefaultApiUrl, nil
}

// resolveConnectUrl implements the 3-tier precedence for the connect
// URL: --connect_url flag > saved network config > DefaultConnectUrl.
func resolveConnectUrl(opts docopt.Opts) (string, error) {
	if connectUrl, err := opts.String("--connect_url"); err == nil {
		return connectUrl, nil
	}
	cfg, ok, err := readNetworkConfig()
	if err != nil {
		return "", err
	}
	if ok {
		return cfg.ConnectUrl, nil
	}
	return DefaultConnectUrl, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestResolveApiUrlPrecedence|TestResolveConnectUrlPrecedence' -v`

Expected: PASS (both tests).

- [ ] **Step 5: Migrate the four call sites**

In `miner/run.go`, inside `auth()`, replace:

```go
	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}
```

with:

```go
	apiUrl, err := resolveApiUrl(opts)
	if err != nil {
		panic(err)
	}
```

In `miner/run.go`, inside `provide()`, replace:

```go
	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}

	connectUrl, err := opts.String("--connect_url")
	if err != nil {
		connectUrl = DefaultConnectUrl
	}
```

with:

```go
	apiUrl, err := resolveApiUrl(opts)
	if err != nil {
		panic(err)
	}

	connectUrl, err := resolveConnectUrl(opts)
	if err != nil {
		panic(err)
	}
```

In `miner/sn.go`, inside `walletSet()`, replace:

```go
	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}
```

with:

```go
	apiUrl, err := resolveApiUrl(opts)
	if err != nil {
		panic(err)
	}
```

In `miner/sn.go`, inside `claim()`, replace:

```go
	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}
```

with:

```go
	apiUrl, err := resolveApiUrl(opts)
	if err != nil {
		panic(err)
	}
```

- [ ] **Step 6: Build and run the full miner test suite to confirm no regressions**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go build ./miner/... && go test ./miner/... -v`

Expected: build succeeds, all tests pass (including the pre-existing tests in `main_test.go` and `sn_test.go`).

- [ ] **Step 7: Commit**

```bash
cd /Users/ryanmello/Documents/GitHub/sn
git add miner/network.go miner/network_test.go miner/run.go miner/sn.go
git commit -m "feat(miner): resolve api_url/connect_url via flag, saved config, then default"
```

---

### Task 3: `choose_network` CLI subcommand

**Files:**
- Modify: `miner/run.go` (docopt usage string in `mainUsage()`, and `Run()` dispatch)
- Create: `miner/network_cmd.go`
- Test: `miner/main_test.go` (append), `miner/network_test.go` (append)

**Interfaces:**
- Consumes: `writeNetworkConfig`, `resetNetworkConfig` from Task 1.
- Produces: `func chooseNetworkCmd(opts docopt.Opts)` — invoked from `Run()`.

- [ ] **Step 1: Write the failing docopt parsing test**

Append to `miner/main_test.go`:

```go
func TestMainUsageChooseNetwork(t *testing.T) {
	opts := parseArgsForTest(t, []string{"choose_network", "https://example.com", "wss://example.com"})
	if chooseNetwork, _ := opts.Bool("choose_network"); !chooseNetwork {
		t.Fatalf("choose_network not set")
	}
	apiUrl, err := opts.String("<api_url>")
	if err != nil || apiUrl != "https://example.com" {
		t.Fatalf("<api_url> = %q, err %v", apiUrl, err)
	}
	connectUrl, err := opts.String("<connect_url>")
	if err != nil || connectUrl != "wss://example.com" {
		t.Fatalf("<connect_url> = %q, err %v", connectUrl, err)
	}
}

func TestMainUsageChooseNetworkReset(t *testing.T) {
	opts := parseArgsForTest(t, []string{"choose_network", "--reset"})
	if chooseNetwork, _ := opts.Bool("choose_network"); !chooseNetwork {
		t.Fatalf("choose_network not set")
	}
	if reset, _ := opts.Bool("--reset"); !reset {
		t.Fatalf("--reset not set")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestMainUsageChooseNetwork|TestMainUsageChooseNetworkReset' -v`

Expected: FAIL — docopt raises a parse error because `choose_network` is not yet in the usage string (the `parseArgsForTest` helper calls `t.Fatalf` on parse error).

- [ ] **Step 3: Add `choose_network` to the docopt usage string**

In `miner/run.go`, inside `mainUsage()`, find this block (currently the last two Usage lines before `Options:`):

```go
    provider proxy auth add [<key>] <proxy_user> <proxy_password> [-f]
    provider proxy auth remove [<key>] [--all]
    provider proxy add [<key_address>...] [--proxy_file=<proxy_file>] [-f]
    provider proxy remove [<key_address>...] [--all]

Options:
```

Replace it with:

```go
    provider proxy auth add [<key>] <proxy_user> <proxy_password> [-f]
    provider proxy auth remove [<key>] [--all]
    provider proxy add [<key_address>...] [--proxy_file=<proxy_file>] [-f]
    provider proxy remove [<key_address>...] [--all]
    provider choose_network <api_url> <connect_url>
    provider choose_network --reset

Options:
```

Then, in the `Options:` block, find:

```go
    --api_url=<api_url>              Specify a custom API URL to use.
    --connect_url=<connect_url>      Specify a custom connect URL to use.
```

Replace it with:

```go
    --api_url=<api_url>              Specify a custom API URL to use.
    --connect_url=<connect_url>      Specify a custom connect URL to use.
    <api_url>                        API URL to save as the chosen network (http:// or https://).
    <connect_url>                    Connect URL to save as the chosen network (ws:// or wss://).
    --reset                          With choose_network, clear the saved network and revert to the main network.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestMainUsageChooseNetwork|TestMainUsageChooseNetworkReset' -v`

Expected: PASS (both tests).

- [ ] **Step 5: Write the failing command-behavior tests**

Append to `miner/network_test.go`:

```go
func TestChooseNetworkCmdSaves(t *testing.T) {
	withTempHome(t)
	opts := parseArgsForTest(t, []string{"choose_network", "https://example.com", "wss://example.com"})
	chooseNetworkCmd(opts)

	cfg, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if !ok {
		t.Fatalf("expected network config to be saved")
	}
	if cfg.ApiUrl != "https://example.com" || cfg.ConnectUrl != "wss://example.com" {
		t.Fatalf("saved config = %+v, want api_url=https://example.com connect_url=wss://example.com", cfg)
	}
}

func TestChooseNetworkCmdReset(t *testing.T) {
	withTempHome(t)
	if err := writeNetworkConfig("https://example.com", "wss://example.com"); err != nil {
		t.Fatalf("writeNetworkConfig: unexpected error: %s", err)
	}

	opts := parseArgsForTest(t, []string{"choose_network", "--reset"})
	chooseNetworkCmd(opts)

	_, ok, err := readNetworkConfig()
	if err != nil {
		t.Fatalf("readNetworkConfig: unexpected error: %s", err)
	}
	if ok {
		t.Fatalf("expected network config to be cleared after reset")
	}
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestChooseNetworkCmdSaves|TestChooseNetworkCmdReset' -v`

Expected: FAIL — compile error, `chooseNetworkCmd` is undefined.

- [ ] **Step 7: Implement `chooseNetworkCmd` and wire it into `Run()`**

Create `miner/network_cmd.go`:

```go
package miner

// network_cmd.go — the `provider choose_network` command handler.
// Saving/resetting logic lives in network.go; this file owns the CLI
// glue (argument extraction, user-facing output).

import (
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
)

// chooseNetworkCmd implements `provider choose_network <api_url>
// <connect_url>` and `provider choose_network --reset`.
func chooseNetworkCmd(opts docopt.Opts) {
	if reset, _ := opts.Bool("--reset"); reset {
		if err := resetNetworkConfig(); err != nil {
			fmt.Printf("failed to reset network: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("network reset to the main network")
		return
	}

	apiUrl, err := opts.String("<api_url>")
	if err != nil {
		fmt.Printf("missing <api_url>: %s\n", err)
		os.Exit(1)
	}
	connectUrl, err := opts.String("<connect_url>")
	if err != nil {
		fmt.Printf("missing <connect_url>: %s\n", err)
		os.Exit(1)
	}

	if err := writeNetworkConfig(apiUrl, connectUrl); err != nil {
		fmt.Printf("network not saved: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("network saved: api_url=%s connect_url=%s\n", apiUrl, connectUrl)
}
```

In `miner/run.go`, inside `Run()`, find:

```go
	} else if authProvide, _ := opts.Bool("auth-provide"); authProvide {
		auth(opts)
		provide(opts)
	}
}
```

Replace it with:

```go
	} else if authProvide, _ := opts.Bool("auth-provide"); authProvide {
		auth(opts)
		provide(opts)
	} else if chooseNetwork, _ := opts.Bool("choose_network"); chooseNetwork {
		chooseNetworkCmd(opts)
	}
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go test ./miner/ -run 'TestChooseNetworkCmdSaves|TestChooseNetworkCmdReset' -v`

Expected: PASS (both tests).

- [ ] **Step 9: Run the full miner test suite and build**

Run: `cd /Users/ryanmello/Documents/GitHub/sn && go build ./miner/... ./cli/... && go test ./miner/... -v`

Expected: build succeeds (including `cli/miner`, which depends on `miner`), all tests pass.

- [ ] **Step 10: Commit**

```bash
cd /Users/ryanmello/Documents/GitHub/sn
git add miner/run.go miner/network_cmd.go miner/network_test.go miner/main_test.go
git commit -m "feat(miner): add choose_network CLI subcommand"
```

- [ ] **Step 11: Push the branch**

```bash
cd /Users/ryanmello/Documents/GitHub/sn
git push origin beta/custom-server
```

---

## Self-Review

**Spec coverage:**
- `choose_network <api_url> <connect_url>` command: Task 3.
- `choose_network --reset`: Task 3.
- URL scheme validation (http/https, ws/wss): Task 1.
- Storage at `~/.urnetwork/network.json` via `providerStatePath`: Task 1.
- 3-tier precedence (flag > saved > default), applied at all 4 call sites (`auth`, `provide`, `walletSet`, `claim`): Task 2.
- Tests use isolated `HOME` via `t.Setenv`, not the real `~/.urnetwork`: Task 1 (`withTempHome` helper), reused in Tasks 2 and 3.

**Placeholder scan:** No TBD/TODO; every step has complete code; no "similar to Task N" references — full code repeated in Task 3 rather than referencing Task 1/2.

**Type consistency:** `networkConfig{ApiUrl, ConnectUrl}` defined in Task 1 is used identically in Tasks 2 and 3. `resolveApiUrl`/`resolveConnectUrl` signatures (`func(opts docopt.Opts) (string, error)`) declared in Task 2's Interfaces block match their Step 3 implementation and their Task 2 Step 5 call-site usage exactly. `chooseNetworkCmd(opts docopt.Opts)` declared in Task 3's Interfaces matches its Step 7 implementation and its `Run()` wiring.
