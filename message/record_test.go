// The record types, the two ladders, and the gate that keeps the class/bucket join in
// one place.
//
// Two things are being observed here and they fail in opposite directions. The first is
// that the wire alphabet is exactly the nine bytes master section 8 admits and that the
// split and the join are inverses over it — asserted by asking about all 256 bytes and
// all 65536 class/bucket pairs rather than by writing the legal ones down, so a parser
// that widened tomorrow widens the derived set and fails here instead of quietly
// accepting a byte no other implementation will. The second is that no other file
// rebuilds the join out of arithmetic, which needs a walk of the tree rather than a
// list of files, and a positive control so that "found nothing" cannot mean "the
// matchers stopped matching".
//
// The pinned literals are pinned on purpose. Spec B indexes and CHECKs on the
// ct_body column of the size ladder and restates the eph ladder, so a drift in either
// is a cross spec break that no round trip property would notice: both directions would
// still agree with each other, and with nobody else.
package message

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// A split retention class: the two halves of the wire byte, as go carries them.
type classBucket struct {
	class  RetentionClass
	bucket uint8
}

// The whole legal wire alphabet, derived by asking the split about every one of the 256
// bytes rather than by writing the nine down. Everything below reads its universe out
// of this, so a parser that accepted a tenth byte would carry that byte into every
// assertion that follows and be caught by the one that pins the set.
func acceptedWireBytes(t *testing.T) map[byte]classBucket {
	t.Helper()
	accepted := map[byte]classBucket{}
	for value := 0; value <= 0xFF; value++ {
		wire := byte(value)
		class, bucket, err := RetentionClassOf(wire)
		if err != nil {
			continue
		}
		accepted[wire] = classBucket{class: class, bucket: bucket}
	}
	if len(accepted) == 0 {
		t.Fatal("the split accepted no byte at all, so every assertion below would hold vacuously")
	}
	return accepted
}

// The nine bytes of master section 8, the one place in this file they are written out.
// The set under test is computed; this is what it is compared against, and a widening
// or a narrowing of the parser moves the computed set off it.
func TestRetentionClassOfAcceptsExactlyTheNineLegalBytes(t *testing.T) {
	accepted := []int{}
	for wire := range acceptedWireBytes(t) {
		accepted = append(accepted, int(wire))
	}
	slices.Sort(accepted)
	want := []int{0x00, 0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}
	if !slices.Equal(accepted, want) {
		t.Errorf("the split accepts %v, want exactly %v; 0x03..0x0f and 0x16..0xff are all errors", accepted, want)
	}
}

// The round trip over the whole byte space: every byte the split accepts must rejoin to
// itself, and every byte it refuses must leave the caller holding nothing usable.
func TestRetentionClassRoundTripsEveryByteTheSplitAccepts(t *testing.T) {
	roundTripped := 0
	for value := 0; value <= 0xFF; value++ {
		wire := byte(value)
		class, bucket, err := RetentionClassOf(wire)
		if err != nil {
			// a refusal that still hands back an encodable class is a refusal a caller
			// can walk straight past, which is the failure mode the guardrail on fatal
			// errors exists to stop
			if joined, joinErr := RetentionClassWire(class, bucket); joinErr == nil {
				t.Errorf("0x%02x was refused but the class it returned still joins to 0x%02x", wire, joined)
			}
			continue
		}
		joined, err := RetentionClassWire(class, bucket)
		if err != nil {
			t.Errorf("0x%02x split to class %d bucket %d, which the join then refused: %v", wire, class, bucket, err)
			continue
		}
		if joined != wire {
			t.Errorf("0x%02x split to class %d bucket %d and rejoined as 0x%02x", wire, class, bucket, joined)
			continue
		}
		roundTripped++
	}
	if roundTripped != 9 {
		t.Errorf("%d bytes round tripped, want the 9 legal ones", roundTripped)
	}
}

// The other order, and the distinctness the round trip alone does not show. A join that
// dropped the eph bucket would still round trip in the byte to pair to byte direction
// if the split dropped it too; what catches that pair of changes is that nine distinct
// bytes must produce nine distinct (class, bucket) pairs and each pair must come back
// to the byte it came from.
func TestRetentionClassJoinAndSplitAreInversesInBothOrders(t *testing.T) {
	accepted := acceptedWireBytes(t)
	pairs := map[classBucket]byte{}
	for wire, pair := range accepted {
		joined, err := RetentionClassWire(pair.class, pair.bucket)
		if err != nil {
			t.Errorf("class %d bucket %d came out of 0x%02x but the join refused it: %v", pair.class, pair.bucket, wire, err)
			continue
		}
		if joined != wire {
			t.Errorf("class %d bucket %d joined to 0x%02x, want the 0x%02x it was split from", pair.class, pair.bucket, joined, wire)
		}
		class, bucket, err := RetentionClassOf(joined)
		if err != nil {
			t.Errorf("class %d bucket %d joined to 0x%02x, which the split then refused: %v", pair.class, pair.bucket, joined, err)
			continue
		}
		if (classBucket{class: class, bucket: bucket}) != pair {
			t.Errorf("class %d bucket %d joined to 0x%02x and split back to class %d bucket %d", pair.class, pair.bucket, joined, class, bucket)
		}
		if earlier, repeated := pairs[pair]; repeated {
			t.Errorf("0x%02x and 0x%02x both split to class %d bucket %d", earlier, wire, pair.class, pair.bucket)
		}
		pairs[pair] = wire
	}
	if len(pairs) != len(accepted) {
		t.Errorf("%d accepted bytes produced only %d distinct class/bucket pairs", len(accepted), len(pairs))
	}
}

// The join over its whole domain: all 65536 (class, bucket) pairs, of which exactly the
// nine the wire alphabet names may be encodable. The legal set is derived from the
// split, so the two functions are pinned to one another rather than each to a list.
func TestRetentionClassWireAcceptsExactlyTheLegalPairs(t *testing.T) {
	legalWireOfPair := map[classBucket]byte{}
	for wire, pair := range acceptedWireBytes(t) {
		legalWireOfPair[pair] = wire
	}
	disagreements := 0
	samples := []string{}
	note := func(format string, args ...any) {
		disagreements++
		if len(samples) < 8 {
			samples = append(samples, fmt.Sprintf(format, args...))
		}
	}
	for classValue := 0; classValue <= 0xFF; classValue++ {
		for bucketValue := 0; bucketValue <= 0xFF; bucketValue++ {
			pair := classBucket{class: RetentionClass(classValue), bucket: uint8(bucketValue)}
			wire, err := RetentionClassWire(pair.class, pair.bucket)
			want, legal := legalWireOfPair[pair]
			switch {
			case legal && err != nil:
				note("class %d bucket %d is legal but the join refused it: %v", classValue, bucketValue, err)
			case legal && wire != want:
				note("class %d bucket %d joined to 0x%02x, want 0x%02x", classValue, bucketValue, wire, want)
			case !legal && err == nil:
				note("class %d bucket %d is not on the wire but the join produced 0x%02x", classValue, bucketValue, wire)
			case !legal:
				// the byte handed back with a refusal must itself be unusable, or a
				// caller that ignored the error still writes a record
				if _, _, splitErr := RetentionClassOf(wire); splitErr == nil {
					note("class %d bucket %d was refused but returned the legal byte 0x%02x", classValue, bucketValue, wire)
				}
			}
		}
	}
	if 0 < disagreements {
		t.Errorf("%d of the 65536 class/bucket pairs disagree with the wire alphabet; first %d: %s", disagreements, len(samples), strings.Join(samples, "; "))
	}
	if len(legalWireOfPair) != 9 {
		t.Errorf("the wire alphabet named %d distinct pairs, want 9", len(legalWireOfPair))
	}
}

// The leak the split of the two fields exists to prevent. A bucket only means anything
// under eph, and the tempting implementation of the join ignores it everywhere else and
// returns 0x00 for permanent — which stores a record as though the caller's belief
// about the bucket had been right. Every non eph class is crossed with every bucket
// from 1 to 255, and the classes are read out of the wire alphabet rather than listed.
func TestEphBucketNeverLeaksIntoANonEphClass(t *testing.T) {
	nonEphClasses := map[RetentionClass]bool{}
	for _, pair := range acceptedWireBytes(t) {
		if pair.class != RetentionEph {
			nonEphClasses[pair.class] = true
		}
	}
	if len(nonEphClasses) != 3 {
		t.Errorf("the wire alphabet named %d non eph classes, want 3", len(nonEphClasses))
	}
	for class := range nonEphClasses {
		// the zero bucket is the legal one for these classes, so the refusals below
		// are about the bucket and not about the class
		if _, err := RetentionClassWire(class, 0); err != nil {
			t.Errorf("class %d with no bucket was refused: %v", class, err)
		}
		for bucketValue := 1; bucketValue <= 0xFF; bucketValue++ {
			wire, err := RetentionClassWire(class, uint8(bucketValue))
			if err == nil {
				t.Errorf("class %d carrying eph bucket %d was silently encoded as 0x%02x", class, bucketValue, wire)
				continue
			}
			if !errors.Is(err, ErrEphBucketOnNonEphClass) {
				t.Errorf("class %d carrying eph bucket %d was refused with %v, want %v", class, bucketValue, err, ErrEphBucketOnNonEphClass)
			}
		}
	}
}

// The size ladder, pinned by value. The right hand column is the one spec B indexes and
// CHECKs on, so these five literals are a cross spec contract and not an internal
// detail: a change here that both ladder functions agreed on would still break every
// stored record's length check.
func TestSizeBucketLadderIsPinned(t *testing.T) {
	wantBodyBytes := []int{256, 1024, 4096, 16384, 65536}
	wantCtBodyBytes := []int{272, 1040, 4112, 16400, 65552}
	for bucket := range wantBodyBytes {
		if body := SizeBucketBytes(SizeBucket(bucket)); body != wantBodyBytes[bucket] {
			t.Errorf("size bucket %d has body %d bytes, want %d", bucket, body, wantBodyBytes[bucket])
		}
		if ctBody := SizeBucketCtBodyBytes(SizeBucket(bucket)); ctBody != wantCtBodyBytes[bucket] {
			t.Errorf("size bucket %d has ct_body %d bytes, want %d", bucket, ctBody, wantCtBodyBytes[bucket])
		}
	}
	if SizeBucketBlob != SizeBucket(len(wantBodyBytes)) {
		t.Errorf("the blob rung is %d, want the rung just past the five with a body", SizeBucketBlob)
	}
	// the blob rung and everything past the ladder have no inline body, and neither may
	// answer anything a caller could spend as a length
	for value := int(SizeBucketBlob); value <= 0xFF; value++ {
		if body := SizeBucketBytes(SizeBucket(value)); 0 <= body {
			t.Errorf("size bucket %d has no inline body but reports %d body bytes", value, body)
		}
		if ctBody := SizeBucketCtBodyBytes(SizeBucket(value)); 0 <= ctBody {
			t.Errorf("size bucket %d has no inline body but reports %d ct_body bytes", value, ctBody)
		}
	}
}

// The relation between the two size functions, over every rung, derived rather than
// listed: whatever the ladder says, the ciphertext is the body plus the 16 byte aead
// tag and nothing else. This is what stops the two functions drifting apart in a change
// that updated only one of the pinned columns above.
func TestSizeBucketCtBodyIsTheBodyPlusTheAeadTag(t *testing.T) {
	rungsWithABody := 0
	for value := 0; value <= 0xFF; value++ {
		bucket := SizeBucket(value)
		body := SizeBucketBytes(bucket)
		ctBody := SizeBucketCtBodyBytes(bucket)
		if body < 0 {
			if 0 <= ctBody {
				t.Errorf("size bucket %d has no body length but reports a ct_body of %d", value, ctBody)
			}
			continue
		}
		if ctBody != body+16 {
			t.Errorf("size bucket %d has body %d and ct_body %d; ct_body must be the body plus the 16 byte aead tag", value, body, ctBody)
		}
		rungsWithABody++
	}
	if rungsWithABody != 5 {
		t.Errorf("%d rungs carry a body, want the 5 of the ladder", rungsWithABody)
	}
}

// The eph ladder, pinned by value for the same cross spec reason as the size ladder,
// with bucket 0 held to the transient rung's contract: it is never persisted, so it has
// no window a caller could turn into an expiry.
func TestEphBucketSecondsLadderIsPinned(t *testing.T) {
	wantSeconds := []int{1: 3600, 2: 28800, 3: 86400, 4: 604800, 5: 2419200}
	for bucket := 1; bucket < len(wantSeconds); bucket++ {
		if seconds := EphBucketSeconds(uint8(bucket)); seconds != wantSeconds[bucket] {
			t.Errorf("eph bucket %d is %d seconds, want %d", bucket, seconds, wantSeconds[bucket])
		}
	}
	if seconds := EphBucketSeconds(0); 0 <= seconds {
		t.Errorf("eph bucket 0 is the transient rung and is never persisted, but it reports a window of %d seconds", seconds)
	}
	for bucket := len(wantSeconds); bucket <= 0xFF; bucket++ {
		if seconds := EphBucketSeconds(uint8(bucket)); 0 <= seconds {
			t.Errorf("eph bucket %d is not on the ladder but reports a window of %d seconds", bucket, seconds)
		}
	}
	// strictly increasing, so a swap of two rungs is a failure twice over rather than a
	// pair of literals that still add up
	for bucket := 2; bucket < len(wantSeconds); bucket++ {
		if EphBucketSeconds(uint8(bucket)) <= EphBucketSeconds(uint8(bucket-1)) {
			t.Errorf("eph bucket %d is not longer than bucket %d", bucket, bucket-1)
		}
	}
}

// The two ladders answer over exactly the buckets the wire admits, derived from the
// alphabet: every eph byte on the wire names a rung, and no rung exists that the wire
// cannot name. A ladder that grew a seventh rung would put a window behind a byte no
// reader accepts, which is a record nobody can prune on and everybody refuses.
func TestEphLadderCoversExactlyTheBucketsTheWireAdmits(t *testing.T) {
	wireBuckets := map[uint8]bool{}
	for _, pair := range acceptedWireBytes(t) {
		if pair.class == RetentionEph {
			wireBuckets[pair.bucket] = true
		}
	}
	if len(wireBuckets) != 6 {
		t.Errorf("the wire alphabet named %d eph buckets, want 6", len(wireBuckets))
	}
	for bucket := 0; bucket <= 0xFF; bucket++ {
		onTheWire := wireBuckets[uint8(bucket)]
		seconds := EphBucketSeconds(uint8(bucket))
		// bucket 0 is on the wire and has no window on purpose; it is the one rung
		// where the two answers legitimately differ
		if bucket == 0 {
			continue
		}
		if onTheWire && seconds <= 0 {
			t.Errorf("eph bucket %d is on the wire but has no retention window", bucket)
		}
		if !onTheWire && 0 < seconds {
			t.Errorf("eph bucket %d has a window of %d seconds but no wire byte names it", bucket, seconds)
		}
	}
}

// ── the gate: the join happens in one file and nowhere else ──────────────────────
//
// Spec A section 5.1 bans four expression shapes — class<<4, class|bucket, 16+bucket
// and class*16 — anywhere but the two functions in record.go. The ban is the mechanical
// half of the argument in those functions' comments: a second join is a second place
// the class and the bucket can be conflated, and the conflation is silent.
//
// Nothing below rests on a scan having run, for the reason mls/crypto_forbidden_test.go
// gives at length and this file follows: a scanner that finds nothing because it is
// broken reports exactly what one that finds nothing because the tree is clean reports.
// So the scan refuses a root it could not read or that held no go source; every matcher
// is a function the gates and a positive control both call; the control feeds it a
// fixture committing all four shapes, so a matcher that stopped matching fails there
// rather than passing the tree quietly; and a second fixture writes all four shapes in
// prose and does the legal thing, so "not reported" means "allowed or absent" rather
// than "the matchers are asleep".

// The trees the ban covers, relative to this package's directory. connect itself is not
// among them and cannot be: it is the parent, it may not import either of these
// packages, and its data path is full of unrelated bit arithmetic that these matchers
// would report on. The sdk root is added only when it is really there, since a missing
// root is one the scan refuses outright.
const (
	messageRoot    = "."
	mlsRoot        = "../mls"
	sdkRoot        = "../sdk"
	joinSelfName   = "record_test.go"
	joinControlDir = "testdata/forbidden"
)

// Only record.go may join or split the two halves. The list is what the gate reads and
// what its failure message prints, so a message cannot outlive the rule.
var joinAllowedFiles = []string{"record.go"}

// The scan roots, computed rather than fixed: sdk does not exist in this tree today and
// the day it lands is the day this gate has to start covering it, so its absence is
// logged instead of assumed.
func joinScanRoots(t *testing.T) []string {
	t.Helper()
	roots := []string{messageRoot, mlsRoot}
	if entry, err := os.Stat(sdkRoot); err == nil && entry.IsDir() {
		roots = append(roots, sdkRoot)
	} else {
		t.Logf("%s is not in this tree, so the gate covers %v; it joins the roots the day it appears", sdkRoot, roots)
	}
	return roots
}

// One banned expression shape, with the name spec A gives it so a failure reads as the
// rule rather than as a regular expression.
type joinShape struct {
	name    string
	pattern *regexp.Regexp
}

// The operand fragments the shapes are built from. An operand is recognised by its
// name, which is how a matcher tells a join of a class and a bucket from arithmetic
// that happens to use the same operator: identifiers in this tree carry the words the
// spec uses. The trailing close parens catch the converted form, uint8(class)|bucket.
const (
	classOperand   = `[a-z0-9_.]*(?:class|retention)[a-z0-9_.]*\)*`
	bucketOperand  = `[a-z0-9_.]*bucket[a-z0-9_.]*\)*`
	ephBaseLiteral = `(?:16|0x10)`
	notDigit       = `(?:[^0-9]|$)`
	// The or shape takes the eph base in hex only. A decimal 16 beside a pipe is the
	// tail of a shift in a varint decoder far more often than it is this join —
	// mls/syntax/varint.go writes uint32(b[i+1])<<16|... and means nothing by it — and a
	// gate that fires there is a gate the next contributor turns off. Nothing is lost:
	// a decimal join still has to name its bucket on the other side of the pipe, which
	// the bucket operand catches.
	ephBaseHex = `0x10`
)

var classBucketJoinShapes = []joinShape{
	// class<<4. Matched on the shift alone rather than on an operand, because neither
	// package packs bits: there is no other reason to shift a value by exactly four
	// here, and over reporting is the safe direction for a ban list. A legitimate shift
	// by four arriving later is a review conversation, which is the point.
	{name: "class<<4", pattern: regexp.MustCompile(`(?i)<<4` + notDigit)},
	// class|bucket, in either operand order, with either half named or the eph base
	// written as a literal. The trailing and leading non pipe is what keeps a logical
	// or out of the report.
	{name: "class|bucket", pattern: regexp.MustCompile(
		`(?i)(?:(?:` + classOperand + `|` + bucketOperand + `|` + ephBaseHex + `)\|(?:[^|]|$))` +
			`|(?:(?:^|[^|])\|(?:` + classOperand + `|` + bucketOperand + `|` + ephBaseHex + `))`)},
	// 16+bucket, in either order, with the base written as a literal or named.
	{name: "16+bucket", pattern: regexp.MustCompile(
		`(?i)(?:(?:` + ephBaseLiteral + `|` + classOperand + `)\+` + bucketOperand + `)` +
			`|(?:` + bucketOperand + `\+(?:` + ephBaseLiteral + notDigit + `|` + classOperand + `))`)},
	// class*16, in either order.
	{name: "class*16", pattern: regexp.MustCompile(
		`(?i)(?:` + classOperand + `\*` + ephBaseLiteral + notDigit + `)` +
			`|(?:` + ephBaseLiteral + `\*` + classOperand + `)`)},
}

// One walk's result: the text of every go file found, keyed by slash separated path,
// and how many files each root contributed. The per root count is what separates "the
// roots are clean" from "a root was never read".
type joinScan struct {
	sourceTexts    map[string]string
	rootFileCounts map[string]int
}

// Walks each root and collects go source. A directory named testdata or interop is
// skipped unless a root names it outright, which is how the controls reach their
// fixture and nothing else reaches it.
//
// A root that cannot be walked and a root that yielded no go file are both errors,
// because either one produces a scan that reports every gate clean without having read
// any code. The error is returned rather than failed on so that the refusal can be
// tested directly instead of asserted about.
func scanJoinSources(roots []string) (joinScan, error) {
	scan := joinScan{
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

// The scan every gate starts from, with a failed walk fatal rather than reported: every
// assertion downstream is meaningless if the source was never read.
func mustScanJoinSources(t *testing.T, roots []string) joinScan {
	t.Helper()
	scan, err := scanJoinSources(roots)
	if err != nil {
		t.Fatalf("scanning %v: %v", roots, err)
	}
	return scan
}

// Every scanned file except this one, with the exemption counted so it stays at one.
// This file has to quote all four banned shapes to match them, so it is the one file no
// matcher may run against, and a second file cannot quietly join it and become a place
// to hide a real join.
func joinSourcesUnderGate(t *testing.T, scan joinScan) map[string]string {
	t.Helper()
	gated := map[string]string{}
	exempt := 0
	for path, text := range scan.sourceTexts {
		if filepath.Base(path) == joinSelfName {
			exempt++
			continue
		}
		gated[path] = text
	}
	if exempt != 1 {
		t.Errorf("%d scanned files carry the self exemption, want exactly 1 named %s", exempt, joinSelfName)
	}
	return gated
}

// One file's text with comments blanked out and line positions preserved, so a failure
// names the line a reader will find. Blanking rather than deleting keeps a stripped line
// from joining the two around it into a shape neither of them had.
//
// Comments are stripped because these gates are about expressions, while the comment
// explaining why the join is confined is the comment a reader most wants: record.go and
// this file both write all four banned shapes in prose for exactly that reason, and a
// gate that fires on the sentence teaching the rule is a gate the next contributor
// deletes. Line endings are normalised first — autocrlf is on at system scope on this
// platform, and a matcher anchored on a line that ends in a carriage return is a gate
// that has already stopped demanding anything.
func joinCodeOf(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
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

// One line with every space removed, so that class | bucket and class|bucket are the
// same shape to a matcher and a contributor cannot get past the gate with gofmt.
func squeezed(line string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, line)
}

// Every line of one file's code that commits shape, squeezed as the matcher sees it, so
// a failure prints the expression rather than a line number. The gates and the controls
// both call this, so a change that makes it stop matching fails the control instead of
// passing every file in the tree.
func joinShapeLines(text string, shape joinShape) []string {
	found := []string{}
	for _, line := range strings.Split(joinCodeOf(text), "\n") {
		squeezedLine := squeezed(line)
		if shape.pattern.MatchString(squeezedLine) {
			found = append(found, squeezedLine)
		}
	}
	return found
}

// The scanned paths whose code commits shape and whose base name is not allowed to,
// each with the lines that did it, so a failure is actionable and a control can compare
// an exact set.
func joinViolations(sourceTexts map[string]string, shape joinShape, allowedFiles []string) map[string][]string {
	violations := map[string][]string{}
	for path, text := range sourceTexts {
		if slices.Contains(allowedFiles, filepath.Base(path)) {
			continue
		}
		if lines := joinShapeLines(text, shape); 0 < len(lines) {
			violations[path] = lines
		}
	}
	return violations
}

// The paths of anything keyed by path, sorted, for a failure message that has to show
// what was read. Generic over the value so the scan and the violation report are read
// out by the same function and cannot sort differently.
func joinScannedPaths[V any](byPath map[string]V) []string {
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// One fixture file, missing being fatal rather than empty: an absent fixture would make
// every control assertion below trivially true, which is the failure this half of the
// file exists to rule out.
func joinControlFile(t *testing.T, control joinScan, name string) string {
	t.Helper()
	text, ok := control.sourceTexts[joinControlDir+"/"+name]
	if !ok {
		t.Fatalf("control fixture %s is missing; the scan read %v", name, joinScannedPaths(control.sourceTexts))
	}
	return text
}

// The gate. Test files are in scope as well as production ones: a test that rebuilds the
// join is a second implementation of it, and the assertion it makes about the wire is
// then an assertion about itself.
func TestClassBucketJoinIsConfinedToRecordGo(t *testing.T) {
	scan := mustScanJoinSources(t, joinScanRoots(t))
	sources := joinSourcesUnderGate(t, scan)
	for _, shape := range classBucketJoinShapes {
		violations := joinViolations(sources, shape, joinAllowedFiles)
		for _, path := range joinScannedPaths(violations) {
			t.Errorf("%s joins the retention class and the eph bucket in the shape %s; only %s may: %v",
				path, shape.name, strings.Join(joinAllowedFiles, " and "), violations[path])
		}
	}
}

// The allowance is only worth having if the join really is in the file it names. A
// record.go that had stopped joining — because the join moved to a helper the matchers
// do not look at, or because it was written in some shape none of them cover — would
// leave the gate above passing over a tree where the rule no longer holds.
func TestTheAllowedFileActuallyJoins(t *testing.T) {
	scan := mustScanJoinSources(t, []string{messageRoot})
	for _, name := range joinAllowedFiles {
		text, ok := scan.sourceTexts[name]
		if !ok {
			t.Fatalf("%s is allowed to join but the scan did not read it; it read %v", name, joinScannedPaths(scan.sourceTexts))
		}
		joins := []string{}
		for _, shape := range classBucketJoinShapes {
			if 0 < len(joinShapeLines(text, shape)) {
				joins = append(joins, shape.name)
			}
		}
		if len(joins) == 0 {
			t.Errorf("%s is the only file allowed to join the class and the bucket, and it commits none of the shapes %v; either the join moved or the matchers no longer see it", name, shapeNames())
		} else {
			t.Logf("%s joins in the shapes %v", name, joins)
		}
	}
}

// The shape names, for a message that has to list what was looked for.
func shapeNames() []string {
	names := make([]string, 0, len(classBucketJoinShapes))
	for _, shape := range classBucketJoinShapes {
		names = append(names, shape.name)
	}
	return names
}

// The positive control. Every matcher must fire on the fixture that commits its shape,
// and the confinement check must report that fixture and nothing else, so a matcher
// that stopped matching fails here rather than issuing the tree a clean bill.
func TestJoinMatchersFlagTheControlFixture(t *testing.T) {
	if len(classBucketJoinShapes) != 4 {
		t.Fatalf("%d shapes are banned, want the 4 of spec A section 5.1", len(classBucketJoinShapes))
	}
	control := mustScanJoinSources(t, []string{joinControlDir})
	text := joinControlFile(t, control, "join.go")
	for _, shape := range classBucketJoinShapes {
		lines := joinShapeLines(text, shape)
		if len(lines) == 0 {
			t.Errorf("the matcher for %s found nothing in the control fixture, so it is no longer a gate", shape.name)
			continue
		}
		t.Logf("%s matched %v", shape.name, lines)
		violations := joinViolations(control.sourceTexts, shape, joinAllowedFiles)
		if !slices.Equal(joinScannedPaths(violations), []string{joinControlDir + "/join.go"}) {
			t.Errorf("the confinement check reported %v for %s, want only the fixture that commits it", joinScannedPaths(violations), shape.name)
		}
	}
}

// The negative half of the control: a fixture that writes all four shapes in prose and
// does the legal thing must be reported by nothing. Without it, a matcher that answered
// yes to every file would pass the positive control above.
func TestJoinMatchersIgnoreTheDocumentedFixture(t *testing.T) {
	control := mustScanJoinSources(t, []string{joinControlDir})
	text := joinControlFile(t, control, "documented.go")
	for _, shape := range classBucketJoinShapes {
		if lines := joinShapeLines(text, shape); 0 < len(lines) {
			t.Errorf("the matcher for %s fired on %v in the fixture that only writes about the shapes", shape.name, lines)
		}
	}
	// and it has to actually contain them, or it controls nothing
	for _, shape := range classBucketJoinShapes {
		if !strings.Contains(text, shape.name) {
			t.Errorf("the documented fixture does not mention %s, so it controls nothing", shape.name)
		}
	}
}

// The coverage guarantee, exercised rather than assumed. A root that is not there and a
// root holding no go source both have to be refused: either one hands every gate above a
// clean result it did not earn. The last two are the case that actually bites — a second
// root that reads nothing while the first reads plenty, which a scan wide total would
// never notice.
func TestJoinScanRefusesARootItCannotCover(t *testing.T) {
	uncoveredRootSets := [][]string{
		{},
		{"../this-package-does-not-exist"},
		{"../mls/testdata/vectors"},
		{messageRoot, "../this-package-does-not-exist"},
		{messageRoot, "../mls/testdata/vectors"},
	}
	for _, roots := range uncoveredRootSets {
		if _, err := scanJoinSources(roots); err == nil {
			t.Errorf("scanning %v succeeded; a root that contributes no source must be refused", roots)
		}
	}
	// and the real roots must pass it, or the refusal above is just "everything fails"
	if _, err := scanJoinSources(joinScanRoots(t)); err != nil {
		t.Errorf("scanning the real roots failed: %v", err)
	}
}

// What the gate actually read, reported rather than trusted. The bookkeeping check is
// the part the scan itself does not do: a per root count that no longer adds up to the
// collected set means files are being counted for a root that did not supply them.
func TestJoinScanCoversEveryRoot(t *testing.T) {
	roots := joinScanRoots(t)
	scan := mustScanJoinSources(t, roots)
	total := 0
	for _, root := range roots {
		t.Logf("root %s contributed %d go files", root, scan.rootFileCounts[root])
		total += scan.rootFileCounts[root]
	}
	if len(scan.sourceTexts) != total {
		t.Errorf("the scan holds %d files while the roots counted %d", len(scan.sourceTexts), total)
	}
	if len(scan.rootFileCounts) != len(roots) {
		t.Errorf("%d roots contributed files, want %d", len(scan.rootFileCounts), len(roots))
	}
}

// The fixture is a file full of real joins, so the gate must be unable to see it. If a
// directory named testdata ever stopped being skipped, the gate would fail on the
// control instead of on the code, which is loud but misleading; this names the reason.
func TestJoinScanSkipsTestdata(t *testing.T) {
	scan := mustScanJoinSources(t, joinScanRoots(t))
	for _, path := range joinScannedPaths(scan.sourceTexts) {
		if strings.HasPrefix(path, "testdata/") || strings.Contains(path, "/testdata/") {
			t.Errorf("the gate read %s; the control fixture and vendored corpora must stay out of scope", path)
		}
	}
}
