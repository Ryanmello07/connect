// the RFC 9420 tree-math test-vector family, family 1 of the sixteen the
// validation and interop harness plan vendors into testdata/vectors.
//
// the entries are plain integers, so this file decodes them itself, but the
// bytes come from the shared loader: one reader of the vendored corpus, one
// place a vendoring mistake surfaces. families whose fields are hex-encoded
// also call MustHex; this one has no hex field.
package mls

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// the directory the validation and interop harness plan vendors the mlswg
// corpus into, named relative to this package so the loader is independent of
// where the test binary is invoked from.
const vectorDir = "testdata/vectors"

// LoadVectorFile reads one vendored mlswg corpus file and splits it into its
// top-level entries without decoding them, so each family owns its own entry
// type while exactly one function reads the corpus off disk.
//
// This is a temporary in-package stand-in. The validation and interop harness
// plan owns this symbol and declares it in mls/vectors_test.go; that file does
// not exist yet, and family 1 cannot wait for it. When it lands the duplicate
// declaration is a build failure by design: delete this one, keep the callers.
//
// It fails the test rather than returning an error because every failure it can
// report — the corpus is absent, the corpus is not a JSON array — is a broken
// checkout rather than a condition any caller could handle.
func LoadVectorFile(t *testing.T, file string) []json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.FromSlash(vectorDir), file))
	if err != nil {
		t.Fatalf("read %s/%s: %v", vectorDir, file, err)
	}
	entries := []json.RawMessage{}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("parse %s/%s as a vector array: %v", vectorDir, file, err)
	}
	return entries
}

// one entry of the family. every relation column is optional: null means the
// function is undefined at that node, which is as much a part of the vector as
// an index is.
type treeMathVector struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []*uint32 `json:"left"`
	Right   []*uint32 `json:"right"`
	Parent  []*uint32 `json:"parent"`
	Sibling []*uint32 `json:"sibling"`
}

// the family file, named relative to testdata/vectors exactly as
// VectorFamily.File is.
const treeMathVectorFile = "tree-math.json"

// the entry count upstream publishes for this family, one per leaf count on
// the ladder. It lives here rather than inside a single test because the
// loader below checks it on every call.
const treeMathVectorCount = 10

// decodes the vendored family through the shared loader, failing the test
// rather than returning an error so every caller is a one-liner.
//
// The count is checked here, in the loader, rather than only in the corpus
// tripwire below. A loader that silently returns nothing passes every caller
// that ranges over its result, and plan p1 shipped exactly that shape before
// needing the same guard. It matters here because every command the plan
// prescribes for the tasks that follow names one test with -run, so none of
// them runs the tripwire: with the guard only there, emptying the corpus
// leaves those vector tests passing over zero entries and asserting nothing.
func loadTreeMathVectors(t *testing.T) []treeMathVector {
	t.Helper()
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	vectors := make([]treeMathVector, 0, len(rawEntries))
	for i, rawEntry := range rawEntries {
		var vector treeMathVector
		if err := json.Unmarshal(rawEntry, &vector); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		vectors = append(vectors, vector)
	}
	// checked on what is handed back, not on what was read. guarding the input
	// count instead looks equivalent and is not: it passes for a loader whose
	// body is later reduced to returning nil, which is the exact regression this
	// guard exists to catch. the first version of this check made that mistake
	// and survived the mutation it was written for.
	if len(vectors) != treeMathVectorCount {
		t.Fatalf("returning %d entries for %s, want %d: a vector test over a short corpus asserts nothing", len(vectors), treeMathVectorFile, treeMathVectorCount)
	}
	return vectors
}

// a tripwire on the corpus itself. the mlswg format is not versioned in the
// file, so a field added upstream would otherwise be vendored and silently
// ignored, and a bump that dropped entries would shrink the gate without
// failing anything.
func TestTreeMathVectorFileShape(t *testing.T) {
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	if len(rawEntries) != 10 {
		t.Fatalf("entries: %d, want 10", len(rawEntries))
	}

	wantFields := []string{"n_leaves", "n_nodes", "root", "left", "right", "parent", "sibling"}
	for i, rawEntry := range rawEntries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		if len(entry) != len(wantFields) {
			t.Fatalf("entry %d: %d fields, want %d — the upstream format changed and the runner must be extended", i, len(entry), len(wantFields))
		}
		for _, field := range wantFields {
			if _, ok := entry[field]; !ok {
				t.Fatalf("entry %d: missing field %s", i, field)
			}
		}
	}

	vectors := loadTreeMathVectors(t)
	wantLeaves := []uint32{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	totalNodes := uint32(0)
	for i, v := range vectors {
		if v.NLeaves != wantLeaves[i] {
			t.Fatalf("entry %d: n_leaves %d, want %d", i, v.NLeaves, wantLeaves[i])
		}
		// kept for the reader, not for coverage: the row above pins n_leaves to
		// an exact power of two, so nothing that reaches here can fail this. it
		// states the property the ladder exists to express, and goes live the
		// day the ladder is relaxed to a range.
		if v.NLeaves&(v.NLeaves-1) != 0 {
			t.Fatalf("entry %d: n_leaves %d is not a power of two", i, v.NLeaves)
		}
		// n_nodes is otherwise pinned only in aggregate, by the family total
		// below, and self-consistently, by the column lengths. neither notices
		// node counts moved from one entry to another, so the relation that
		// defines a full tree is asserted per entry.
		if v.NNodes != 2*v.NLeaves-1 {
			t.Fatalf("entry %d: n_nodes %d, want 2*%d-1 = %d", i, v.NNodes, v.NLeaves, 2*v.NLeaves-1)
		}
		columns := map[string]int{
			"left":    len(v.Left),
			"right":   len(v.Right),
			"parent":  len(v.Parent),
			"sibling": len(v.Sibling),
		}
		for name, length := range columns {
			if uint32(length) != v.NNodes {
				t.Fatalf("entry %d: %s has %d entries, want n_nodes %d", i, name, length, v.NNodes)
			}
		}
		totalNodes += v.NNodes
	}
	// do not delete this line. it is the only caller-side statement of the
	// corpus size, and it catches something the loader's own guard structurally
	// cannot: a loader whose body still builds ten entries but hands back
	// something else. that guard runs before the return, so a return statement
	// reduced to nil walks straight past it, and the sum here is what fails.
	// measured, not assumed - with this line removed, that mutation passes the
	// whole file while the loader's guard is still in place.
	//
	// an earlier revision of this comment said the opposite: "kept for the
	// reader rather than for coverage", reasoning that reaching here meant all
	// ten entries had matched. reaching here means the ladder walked whatever
	// was returned, however much that was. a reader who believed the comment
	// would have deleted the one assertion holding that down.
	if totalNodes != 2036 {
		t.Fatalf("nodes across the family: %d, want 2036", totalNodes)
	}
}
