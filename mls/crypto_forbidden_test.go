// The mechanical half of master section 7.2 and spec A section 5.9, guardrails 1 and 3.
// These walk the source of mls and message rather than grepping in continuous
// integration, so a developer sees the failure before pushing and so the rule travels
// with the code. The banned primitives share one property: for a low order point they
// hand back an all zero shared secret instead of an error, and a caller that logs it and
// continues then encrypts under a key its peer chose.
//
// A scanner that finds nothing because it is broken reports exactly what one that finds
// nothing because the code is clean reports, so nothing below rests on a scan having
// run. Three things hold that. The scan refuses a root it could not read or that held no
// go source, so an empty walk fails rather than issuing a clean bill. Every matcher is a
// function the gates and a positive control both call, and the control feeds it
// testdata/forbidden, a fixture committing every banned act, so a matcher that stopped
// matching fails there rather than passing everything quietly. And that fixture carries
// the other half of each case — the same calls in the file names allowed to make them,
// and every banned token in prose — so "not reported" is pinned to mean "allowed" rather
// than "not present".
//
// The matchers run on code with comments removed. These gates are about call sites and
// an import path, while the comment explaining why a primitive is banned is the comment
// a reader most wants: crypto_errors.go and the x25519 helper both name the banned sdk
// helper in their file comments for exactly that reason, and a gate that fires on the
// sentence teaching the rule is a gate the next contributor deletes. A commented out
// call is not a call, so nothing hides there that could also run. The stripping is line
// based, so a trailing comment on a line of code counts as code — deliberately, since
// telling a real trailing comment from a // inside a string literal needs a lexer, and
// over reporting is the safe direction for a ban list.
package mls

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The two package trees the guardrails cover, relative to this package's directory.
// connect itself is not among them: it is the parent, it may not import either of these
// packages, and its own legacy call sites are a separate migration.
var forbiddenScanRoots = []string{".", "../message"}

// The fixture tree the positive controls scan. It sits under testdata on purpose, which
// is what makes it unreachable from the roots above and unbuildable by the go tool.
const forbiddenControlRoot = "testdata/forbidden"

// Primitives that must not appear anywhere in either package. The first three return an
// all zero secret for a low order point; the fourth is the import that supplies the
// second, banned outright so the package cannot enter the graph at all.
var forbiddenPrimitiveTokens = []string{
	"GenerateSharedSecret",
	"box.Precompute",
	"curve25519.ScalarMult",
	"golang.org/x/crypto/nacl/box",
}

// Guardrail 1. crypto/hkdf.Extract takes the input keying material first and the salt
// second, the reverse of the HKDF-Extract(salt, ikm) every spec text in this project
// writes, so every wrapper here swaps. Confining the call keeps the swap in two
// reviewable files instead of scattering a silent argument transposition.
const hkdfExtractNeedle = "hkdf.Extract("

var hkdfExtractAllowedFiles = []string{"crypto.go", "hpke.go"}

// Guardrail 3. One helper turns an x25519 failure into ErrInvalidPoint, so there is
// exactly one place that could ignore it and that place is reviewed.
const ecdhNeedle = ".ECDH("

var ecdhAllowedFiles = []string{"crypto_x25519.go"}

// This file has to quote every token and every assignment shape it bans, so it is the
// one file no matcher may run against. The exemption is by exact base name and the
// count of files taking it is asserted, so a second file cannot quietly join it and
// become a place to hide a real call.
const forbiddenSelfName = "crypto_forbidden_test.go"

// One walk's result: the text of every go file found, keyed by slash separated path,
// and how many files each root contributed. The per root count is what separates "the
// roots are clean" from "the roots were never read".
type forbiddenScan struct {
	sourceTexts    map[string]string
	rootFileCounts map[string]int
}

// Walks each root and collects go source. Vendored corpora and the interop harness are
// skipped by directory name, except where a root names one outright, which is how the
// controls reach their fixture and nothing else reaches it.
//
// A root that cannot be walked and a root that yielded no go file are both errors,
// because either one produces a scan that reports every gate clean without having read
// the code. Returning the error rather than failing a test is what lets that refusal be
// tested directly instead of asserted about.
func scanSources(roots []string) (forbiddenScan, error) {
	scan := forbiddenScan{
		sourceTexts:    map[string]string{},
		rootFileCounts: map[string]int{},
	}
	if len(roots) == 0 {
		return scan, fmt.Errorf("no roots to scan")
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path != root && (entry.Name() == "testdata" || entry.Name() == "interop") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scan.sourceTexts[filepath.ToSlash(path)] = string(body)
			scan.rootFileCounts[root]++
			return nil
		})
		if err != nil {
			return scan, fmt.Errorf("walk %s: %w", root, err)
		}
		if scan.rootFileCounts[root] == 0 {
			return scan, fmt.Errorf("walk %s read no go files; the scan is broken, not the source", root)
		}
	}
	return scan, nil
}

// The scan every gate starts from, with a failed walk fatal rather than reported: each
// assertion downstream is meaningless if the source was never read.
func mustScanSources(t *testing.T, roots []string) forbiddenScan {
	t.Helper()
	scan, err := scanSources(roots)
	if err != nil {
		t.Fatalf("scanning %v: %v", roots, err)
	}
	return scan
}

// Every scanned file except this one, with the exemption counted so it stays at one.
func sourcesUnderGate(t *testing.T, scan forbiddenScan) map[string]string {
	t.Helper()
	gated := map[string]string{}
	exempt := 0
	for path, text := range scan.sourceTexts {
		if filepath.Base(path) == forbiddenSelfName {
			exempt++
			continue
		}
		gated[path] = text
	}
	if exempt != 1 {
		t.Errorf("%d scanned files carry the self exemption, want exactly 1 named %s", exempt, forbiddenSelfName)
	}
	return gated
}

// The non test half of a scan. The confinement rules are about what ships: a test that
// calls a primitive to assert something about it is not a second call site in the code
// an auditor reads.
func productionSources(sourceTexts map[string]string) map[string]string {
	production := map[string]string{}
	for path, text := range sourceTexts {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		production[path] = text
	}
	return production
}

// One file's text with comments blanked out, line positions preserved so the line based
// matcher below still reports what a reader will find. Blanking rather than deleting
// keeps a stripped line from joining the two lines around it into a shape neither of
// them had.
func codeOf(text string) string {
	lines := strings.Split(text, "\n")
	code := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		if inBlock {
			_, afterClose, closed := strings.Cut(line, "*/")
			if !closed {
				code = append(code, "")
				continue
			}
			inBlock = false
			line = afterClose
		}
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			code = append(code, "")
			continue
		}
		if beforeOpen, afterOpen, opened := strings.Cut(line, "/*"); opened {
			if _, tail, closed := strings.Cut(afterOpen, "*/"); closed {
				line = beforeOpen + tail
			} else {
				inBlock = true
				line = beforeOpen
			}
		}
		code = append(code, line)
	}
	return strings.Join(code, "\n")
}

// Every banned token present in one file's code. The gate and its control both call
// this, so a change that makes it stop matching fails the control instead of passing
// every file in the tree.
func forbiddenTokensIn(text string, tokens []string) []string {
	found := []string{}
	for _, token := range tokens {
		if strings.Contains(codeOf(text), token) {
			found = append(found, token)
		}
	}
	return found
}

// The scanned paths whose code contains needle and whose base name is not allowed,
// sorted so a failure reads the same twice and a control can compare an exact set.
func confinementViolations(sourceTexts map[string]string, needle string, allowedFiles []string) []string {
	violations := []string{}
	for path, text := range sourceTexts {
		if !strings.Contains(codeOf(text), needle) {
			continue
		}
		if !slices.Contains(allowedFiles, filepath.Base(path)) {
			violations = append(violations, path)
		}
	}
	slices.Sort(violations)
	return violations
}

// The lines of code that take an x25519 result and throw it, or its error, away. Both
// spellings of assignment count: secret, _ := priv.ECDH(pub) discards the error exactly
// as secret, _ = priv.ECDH(pub) does, and a line opening with an underscore discards the
// secret. The short declaration form is the one the plan text missed, and it is the one
// a contributor reaches for first.
func discardedEcdhLines(text string) []string {
	discarded := []string{}
	for _, line := range strings.Split(codeOf(text), "\n") {
		if !strings.Contains(line, ecdhNeedle) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "_") ||
			strings.Contains(trimmed, ", _ = ") ||
			strings.Contains(trimmed, ", _ := ") {
			discarded = append(discarded, trimmed)
		}
	}
	return discarded
}

// The scanned paths, sorted, for a failure message that has to show what was read.
func scannedPaths(sourceTexts map[string]string) []string {
	paths := make([]string, 0, len(sourceTexts))
	for path := range sourceTexts {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// One fixture file, missing being fatal rather than empty: an absent fixture would make
// every control assertion below trivially true, which is the failure this file exists to
// rule out.
func controlFile(t *testing.T, control forbiddenScan, name string) string {
	t.Helper()
	text, ok := control.sourceTexts[forbiddenControlRoot+"/"+name]
	if !ok {
		t.Fatalf("control fixture %s is missing; the scan read %v", name, scannedPaths(control.sourceTexts))
	}
	return text
}

// The gate: no file in either package may name a banned primitive in code.
func TestForbiddenPrimitivesAreAbsent(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	for path, text := range sourcesUnderGate(t, scan) {
		for _, token := range forbiddenTokensIn(text, forbiddenPrimitiveTokens) {
			t.Errorf("%s references the forbidden primitive %q", path, token)
		}
	}
}

// The gate on guardrail 1. The allowed names are read out of the list the check itself
// uses, so a message cannot outlive the rule it describes.
func TestHkdfExtractHasOnlyTwoCallSites(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	sources := productionSources(sourcesUnderGate(t, scan))
	for _, path := range confinementViolations(sources, hkdfExtractNeedle, hkdfExtractAllowedFiles) {
		t.Errorf("%s calls %s; only %s may", path, hkdfExtractNeedle, strings.Join(hkdfExtractAllowedFiles, " and "))
	}
}

// The gate on guardrail 3, the call site half.
func TestEcdhHasOneCallSite(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	sources := productionSources(sourcesUnderGate(t, scan))
	for _, path := range confinementViolations(sources, ecdhNeedle, ecdhAllowedFiles) {
		t.Errorf("%s calls %s; only %s may", path, ecdhNeedle, strings.Join(ecdhAllowedFiles, " and "))
	}
}

// The gate on guardrail 3, the ignored error half. Tests are in scope here, unlike the
// confinement gates: a test that shrugs off an x25519 error is a test that would pass on
// a broken refusal.
func TestEcdhResultIsNeverDiscarded(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	for path, text := range sourcesUnderGate(t, scan) {
		for _, line := range discardedEcdhLines(text) {
			t.Errorf("%s discards an x25519 result: %s", path, line)
		}
	}
}

// The positive control for the token matcher, and the negative one beside it: the
// fixture that commits every banned act must yield every banned token, and the fixture
// that only writes about them must yield none. Without the second half, a matcher that
// answered yes to everything would pass the first.
func TestForbiddenTokenMatcherFlagsTheControlFixture(t *testing.T) {
	if len(forbiddenPrimitiveTokens) == 0 {
		t.Fatal("the banned token list is empty, so the gate has nothing to match")
	}
	control := mustScanSources(t, []string{forbiddenControlRoot})
	found := forbiddenTokensIn(controlFile(t, control, "violations.go"), forbiddenPrimitiveTokens)
	if !slices.Equal(found, forbiddenPrimitiveTokens) {
		t.Errorf("the matcher found %v in the control fixture, want all of %v", found, forbiddenPrimitiveTokens)
	}
	for _, name := range []string{"crypto.go", "hpke.go", "crypto_x25519.go", "documented.go"} {
		if found := forbiddenTokensIn(controlFile(t, control, name), forbiddenPrimitiveTokens); len(found) != 0 {
			t.Errorf("the matcher flagged %v in %s, which names them only in comments or not at all", found, name)
		}
	}
}

// The positive control for the guardrail 1 confinement, run through the allowed list the
// gate itself uses. Every fixture file is checked to contain the call before the report
// is compared, so an unreported file means the name was allowed rather than that the
// fixture forgot to make the call.
func TestHkdfConfinementFlagsTheControlFixture(t *testing.T) {
	control := mustScanSources(t, []string{forbiddenControlRoot})
	for _, name := range append([]string{"violations.go"}, hkdfExtractAllowedFiles...) {
		if !strings.Contains(codeOf(controlFile(t, control, name)), hkdfExtractNeedle) {
			t.Fatalf("control fixture %s does not call %s, so it controls nothing", name, hkdfExtractNeedle)
		}
	}
	violations := confinementViolations(control.sourceTexts, hkdfExtractNeedle, hkdfExtractAllowedFiles)
	want := []string{forbiddenControlRoot + "/violations.go"}
	if !slices.Equal(violations, want) {
		t.Errorf("the confinement check reported %v, want %v", violations, want)
	}
}

// The positive control for the guardrail 3 confinement, built the same way.
func TestEcdhConfinementFlagsTheControlFixture(t *testing.T) {
	control := mustScanSources(t, []string{forbiddenControlRoot})
	for _, name := range append([]string{"violations.go"}, ecdhAllowedFiles...) {
		if !strings.Contains(codeOf(controlFile(t, control, name)), ecdhNeedle) {
			t.Fatalf("control fixture %s does not call %s, so it controls nothing", name, ecdhNeedle)
		}
	}
	violations := confinementViolations(control.sourceTexts, ecdhNeedle, ecdhAllowedFiles)
	want := []string{forbiddenControlRoot + "/violations.go"}
	if !slices.Equal(violations, want) {
		t.Errorf("the confinement check reported %v, want %v", violations, want)
	}
}

// The positive control for the discard matcher. The expected set is exact, so a matcher
// that widened to flag every call site fails here as surely as one that stopped matching
// — the fixture's fourth x25519 call takes its error, and the comment beside it spells
// out a discarding line that must stay unreported.
func TestEcdhDiscardMatcherFlagsTheControlFixture(t *testing.T) {
	control := mustScanSources(t, []string{forbiddenControlRoot})
	discarded := discardedEcdhLines(controlFile(t, control, "violations.go"))
	want := []string{
		"_, _ = priv.ECDH(pub)",
		"_, err := priv.ECDH(pub)",
		"secret, _ := priv.ECDH(pub)",
		"shared, _ = priv.ECDH(pub)",
	}
	if !slices.Equal(discarded, want) {
		t.Errorf("the discard matcher reported %v, want %v", discarded, want)
	}
	for _, name := range []string{"crypto_x25519.go", "documented.go"} {
		if lines := discardedEcdhLines(controlFile(t, control, name)); len(lines) != 0 {
			t.Errorf("the discard matcher reported %v in %s, which discards nothing", lines, name)
		}
	}
}

// The coverage guarantee, exercised rather than assumed. A root that is not there and a
// root holding no go source both have to be refused: either one hands every gate above a
// clean result it did not earn. The fourth case is the one that actually bit — a second
// root that reads nothing while the first reads plenty, which a scan wide total would
// never notice.
func TestScanRefusesARootItCannotCover(t *testing.T) {
	uncoveredRootSets := [][]string{
		{},
		{"../this-package-does-not-exist"},
		{"testdata/vectors"},
		{".", "../this-package-does-not-exist"},
		{".", "testdata/vectors"},
	}
	for _, roots := range uncoveredRootSets {
		if _, err := scanSources(roots); err == nil {
			t.Errorf("scanning %v succeeded; a root that contributes no source must be refused", roots)
		}
	}
	// and the real roots must pass it, or the refusal above is just "everything fails"
	if _, err := scanSources(forbiddenScanRoots); err != nil {
		t.Errorf("scanning the real roots failed: %v", err)
	}
}

// What the gates actually read, reported rather than trusted. The bookkeeping check is
// the part the scan itself does not do: a per root count that no longer adds up to the
// collected set means files are being counted for a root that did not supply them.
func TestForbiddenScanCoversEveryRoot(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	total := 0
	for _, root := range forbiddenScanRoots {
		t.Logf("root %s contributed %d go files", root, scan.rootFileCounts[root])
		total += scan.rootFileCounts[root]
	}
	if len(scan.sourceTexts) != total {
		t.Errorf("the scan holds %d files while the roots counted %d", len(scan.sourceTexts), total)
	}
	if len(scan.rootFileCounts) != len(forbiddenScanRoots) {
		t.Errorf("%d roots contributed files, want %d", len(scan.rootFileCounts), len(forbiddenScanRoots))
	}
}

// The fixture is a file full of real violations, so the gates must be unable to see it.
// If a directory named testdata ever stopped being skipped, the gates would fail on the
// control instead of on the code, which is loud but misleading; this names the reason.
func TestForbiddenScanSkipsTheControlFixture(t *testing.T) {
	scan := mustScanSources(t, forbiddenScanRoots)
	for _, path := range scannedPaths(scan.sourceTexts) {
		if strings.HasPrefix(path, "testdata/") || strings.Contains(path, "/testdata/") {
			t.Errorf("the gates read %s; vendored corpora and the control fixture must stay out of scope", path)
		}
	}
}
