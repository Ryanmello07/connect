// The stream index reservation's CONTRACT, held against a file backed reserver that lives here
// and ships nowhere.
//
// Why the implementation under test is a test fake and not production source, restated where a
// reader of the tests meets it: spec A section 8.2 assigns the durable store to sdk's
// MessageStore, method for method, and neither half of the record layer imports an I/O package
// at all. A second durable implementation here would be the second implementation of one thing
// and would make the client half a storage engine. What this file owes instead is that every
// property of the interface is EXECUTABLE now rather than deferred to a package that does not
// exist -- so the fake is the crash injection harness section 5.6's own named test needs, and
// every assertion below is an obligation the unwritten sdk store plan inherits.
//
// The fake is deliberately built in two layers. streamIndexFake is the protocol -- the consumed
// check, the ordering of the flush against the return, the high water -- and streamIndexDurable
// is the medium under it. That seam is what makes "Reserve returns only after the write is
// durable" observable in a go test at all: a real file cannot demonstrate it in process, because
// an unsynced write is still visible to a reader on the same machine. A restart here is a fresh
// streamIndexFake over the same medium, holding nothing the medium did not persist, which is the
// same thing a process death is to a store.
package messagegroup

import (
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The medium a reserver's state survives a process death in.
type streamIndexDurable interface {
	load() (map[string]uint64, error)
	save(image map[string]uint64) error
}

// A real file, written and fsync'd, which is what section 5.6's "fsync'd or equivalent" names.
type streamIndexFileStore struct {
	path  string
	saves int
}

func (self *streamIndexFileStore) load() (map[string]uint64, error) {
	image := map[string]uint64{}
	raw, err := os.ReadFile(self.path)
	if errors.Is(err, os.ErrNotExist) {
		return image, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		index, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, err
		}
		image[fields[0]] = index
	}
	return image, nil
}

func (self *streamIndexFileStore) save(image map[string]uint64) error {
	self.saves += 1
	text := strings.Builder{}
	for _, key := range slices.Sorted(maps.Keys(image)) {
		fmt.Fprintf(&text, "%s %d\n", key, image[key])
	}
	file, err := os.OpenFile(self.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(text.String()); err != nil {
		file.Close()
		return err
	}
	// the flush the contract is about. Everything above this line is a write a crash
	// discards; everything below it survives one.
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// The same medium without the file, for the properties that need ten thousand restarts rather
// than ten. It is durable in exactly the sense that matters here -- a fresh reserver over it
// holds what was saved and nothing else -- and it costs no fsync, which is what makes section
// 5.6's own named test runnable at its stated size.
type streamIndexImageStore struct {
	image map[string]uint64
	saves int
}

func (self *streamIndexImageStore) load() (map[string]uint64, error) {
	copied := map[string]uint64{}
	for key, index := range self.image {
		copied[key] = index
	}
	return copied, nil
}

func (self *streamIndexImageStore) save(image map[string]uint64) error {
	self.saves += 1
	copied := map[string]uint64{}
	for key, index := range image {
		copied[key] = index
	}
	self.image = copied
	return nil
}

// streamIndexFake is the protocol half: the consumed refusal, the durable flush ordered before
// the return, and the high water a ratchet resumes from.
type streamIndexFake struct {
	lock    sync.Mutex
	durable streamIndexDurable
	image   map[string]uint64
	// the indices this instance has told a caller it may use. A reload that came back
	// behind one of these is the rewind ErrStreamIndexRewound names.
	handedOut map[string]uint64
	// an injected flush failure, which is the only way a test can stand between the write
	// and its durability.
	saveErr  error
	reserves int
}

func openStreamIndexFake(durable streamIndexDurable) (*streamIndexFake, error) {
	image, err := durable.load()
	if err != nil {
		return nil, err
	}
	return &streamIndexFake{durable: durable, image: image, handedOut: map[string]uint64{}}, nil
}

// A reserver over a fresh in-memory medium, for the tests that need a working sink and do not
// care what it is made of.
func newStreamIndexMemory() *streamIndexFake {
	fake, err := openStreamIndexFake(&streamIndexImageStore{image: map[string]uint64{}})
	if err != nil {
		panic(err)
	}
	return fake
}

func (self *streamIndexFake) Reserve(groupId []byte, index uint64) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.reserves += 1
	key := hex.EncodeToString(groupId)
	if index <= self.image[key] {
		// not idempotent. "I already have that one" and "I am about to encrypt under that
		// one" are the same call from this interface's side, so the second one is a
		// refusal.
		return fmt.Errorf("%w: index %d, high water %d", ErrStreamIndexConsumed, index, self.image[key])
	}
	proposed := map[string]uint64{}
	for existing, held := range self.image {
		proposed[existing] = held
	}
	proposed[key] = index
	if self.saveErr != nil {
		return self.saveErr
	}
	if err := self.durable.save(proposed); err != nil {
		return err
	}
	// AFTER the flush. Everything below this line is state a caller may rely on, and moving
	// either of these two lines above the save is the whole defect this fake exists to make
	// observable.
	self.image = proposed
	self.handedOut[key] = index
	return nil
}

func (self *streamIndexFake) HighWater(groupId []byte) (uint64, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	// total over the key space: a group never seen is 0 and not an error, so highWater + 1
	// is a well defined start.
	return self.image[hex.EncodeToString(groupId)], nil
}

// reload re-reads the medium, and refuses if it came back behind an index this instance has
// already handed out.
func (self *streamIndexFake) reload() error {
	self.lock.Lock()
	defer self.lock.Unlock()
	image, err := self.durable.load()
	if err != nil {
		return err
	}
	for key, handed := range self.handedOut {
		if image[key] < handed {
			return fmt.Errorf("%w: %s persisted %d and %d was handed out", ErrStreamIndexRewound, key, image[key], handed)
		}
	}
	self.image = image
	return nil
}

// A reserver that refuses everything, for the ordering property one file over.
type streamIndexRefusing struct {
	err      error
	reserves int
}

func (self *streamIndexRefusing) Reserve(groupId []byte, index uint64) error {
	self.reserves += 1
	return self.err
}

func (self *streamIndexRefusing) HighWater(groupId []byte) (uint64, error) { return 0, nil }

// A reserver whose HighWater fails, so a constructor that ignored the read is visible.
type streamIndexUnreadable struct{ err error }

func (self *streamIndexUnreadable) Reserve(groupId []byte, index uint64) error { return nil }

func (self *streamIndexUnreadable) HighWater(groupId []byte) (uint64, error) { return 0, self.err }

var streamIndexGroup = []byte{0x67, 0x72, 0x70, 0x01}

// Property 1: Reserve returns only after the reservation survives a process death.
//
// The mechanism is an injected failure point BETWEEN the write and the flush, which is the only
// thing that can tell "returned" from "durable" -- a sleep cannot, and neither can reading the
// file back in the same process. Three claims, and the third is the one a swallowed flush error
// fails: the error reaches the caller, the medium holds nothing, and the index is still free
// afterwards, so the seal that was refused did not silently consume a nonce.
func TestReserveReturnsOnlyAfterTheReservationIsDurable(t *testing.T) {
	store := &streamIndexFileStore{path: filepath.Join(t.TempDir(), "stream.index")}
	fake, err := openStreamIndexFake(store)
	if err != nil {
		t.Fatalf("open the reserver: %v", err)
	}
	// the happy path first, so the assertion below is about durability and not about the
	// fake being broken
	if err := fake.Reserve(streamIndexGroup, 1); err != nil {
		t.Fatalf("reserve index 1: %v", err)
	}
	restarted, err := openStreamIndexFake(&streamIndexFileStore{path: store.path})
	if err != nil {
		t.Fatalf("restart the reserver: %v", err)
	}
	if got, err := restarted.HighWater(streamIndexGroup); err != nil || got != 1 {
		t.Fatalf("after a restart the high water is %d (%v), want 1; Reserve returned before the write reached the medium", got, err)
	}
	// and now the failure point between the write and the flush
	injected := errors.New("the disk is full")
	fake.saveErr = injected
	if err := fake.Reserve(streamIndexGroup, 2); !errors.Is(err, injected) {
		t.Errorf("Reserve answered %v when the flush failed, want the flush's own error; a swallowed flush error is a reservation that is not one", err)
	}
	afterFailure, err := openStreamIndexFake(&streamIndexFileStore{path: store.path})
	if err != nil {
		t.Fatalf("restart the reserver: %v", err)
	}
	if got, _ := afterFailure.HighWater(streamIndexGroup); got != 1 {
		t.Errorf("the medium holds high water %d after a failed flush, want 1", got)
	}
	// the index is still free, so the refused seal consumed nothing
	fake.saveErr = nil
	if err := fake.Reserve(streamIndexGroup, 2); err != nil {
		t.Errorf("index 2 was refused after its own reservation failed to flush: %v", err)
	}
	if 2 <= store.saves && store.saves != 2 {
		// two successful saves and no more: the failed one never reached the medium
		t.Errorf("the medium was written %d times for two successful reservations", store.saves)
	}
}

// Property 2: TestStreamIndexNeverReused, named by spec A section 5.9 G5 and G11.
//
// Section 5.6 states its shape: ten thousand seal operations with an injected crash after Reserve
// and before the AEAD, the session restarted from the persisted state, and no index ever produced
// twice. SealRecord does not exist until task 11 and the property is not about SealRecord -- it
// is about the reserver plus the restart -- so the crash is injected exactly where the seal would
// have been, and task 11 extends this same test to the real one.
//
// The medium is the in-memory image rather than the file, which is what makes ten thousand
// restarts affordable; TestReserveReturnsOnlyAfterTheReservationIsDurable is where the file and
// its fsync are held.
func TestStreamIndexNeverReused(t *testing.T) {
	const seals = 10000
	store := &streamIndexImageStore{image: map[string]uint64{}}
	produced := map[uint64]int{}
	for seal := 0; seal < seals; seal += 1 {
		// a fresh reserver over the persisted state: this IS the restart
		fake, err := openStreamIndexFake(store)
		if err != nil {
			t.Fatalf("restart %d: %v", seal, err)
		}
		highWater, err := fake.HighWater(streamIndexGroup)
		if err != nil {
			t.Fatalf("high water at restart %d: %v", seal, err)
		}
		index := highWater + 1
		if err := fake.Reserve(streamIndexGroup, index); err != nil {
			t.Fatalf("reserve %d at restart %d: %v", index, seal, err)
		}
		if earlier, isRepeat := produced[index]; isRepeat {
			t.Fatalf("index %d was produced at seal %d and again at seal %d; a reused stream index is a reused nonce under a reused record key",
				index, earlier, seal)
		}
		produced[index] = seal
		// and here the process dies, after the reservation and before the aead. The next
		// iteration is what comes back.
	}
	if len(produced) != seals {
		t.Errorf("%d distinct indices came out of %d seals", len(produced), seals)
	}
	if got, _ := (&streamIndexFake{durable: store, image: store.image}).HighWater(streamIndexGroup); got != seals {
		t.Errorf("the persisted high water is %d after %d seals", got, seals)
	}
}

// Property 3: HighWater never rewinds, and a medium that came back behind an index already
// handed out is a refusal rather than a fresh start.
func TestHighWaterNeverRewinds(t *testing.T) {
	store := &streamIndexImageStore{image: map[string]uint64{}}
	fake, err := openStreamIndexFake(store)
	if err != nil {
		t.Fatalf("open the reserver: %v", err)
	}
	previous := uint64(0)
	for index := uint64(1); index <= 64; index += 1 {
		if err := fake.Reserve(streamIndexGroup, index); err != nil {
			t.Fatalf("reserve %d: %v", index, err)
		}
		got, err := fake.HighWater(streamIndexGroup)
		if err != nil {
			t.Fatalf("high water: %v", err)
		}
		if got < previous {
			t.Fatalf("the high water went from %d to %d", previous, got)
		}
		previous = got
		// a restart in the middle must not move it either
		if err := fake.reload(); err != nil {
			t.Fatalf("reload at %d: %v", index, err)
		}
		if got, _ := fake.HighWater(streamIndexGroup); got != previous {
			t.Fatalf("a reload moved the high water from %d to %d", previous, got)
		}
	}
	// and a medium that lost a flush is ErrStreamIndexRewound, not a fresh start: every
	// index above what it now holds is a nonce this device may already have used
	store.image[hex.EncodeToString(streamIndexGroup)] = 7
	if err := fake.reload(); !errors.Is(err, ErrStreamIndexRewound) {
		t.Errorf("a medium that came back at 7 after 64 was handed out answered %v, want ErrStreamIndexRewound", err)
	}
}

// Property 4: a consumed index is refused and never overwritten, with a typed sentinel.
func TestAConsumedStreamIndexIsRefusedAndNotOverwritten(t *testing.T) {
	fake := newStreamIndexMemory()
	if err := fake.Reserve(streamIndexGroup, 1); err != nil {
		t.Fatalf("reserve 1: %v", err)
	}
	if err := fake.Reserve(streamIndexGroup, 5); err != nil {
		t.Fatalf("reserve 5, a legal gap: %v", err)
	}
	// every index at or below the high water is consumed, including the gap the server's
	// monotonicity rule allows
	for _, index := range []uint64{0, 1, 2, 4, 5} {
		if err := fake.Reserve(streamIndexGroup, index); !errors.Is(err, ErrStreamIndexConsumed) {
			t.Errorf("reserving consumed index %d answered %v, want ErrStreamIndexConsumed", index, err)
		}
	}
	if got, _ := fake.HighWater(streamIndexGroup); got != 5 {
		t.Errorf("the refusals moved the high water to %d, want 5", got)
	}
	if err := fake.Reserve(streamIndexGroup, 6); err != nil {
		t.Errorf("index 6 was refused after the refusals: %v", err)
	}
}

// Property 5: the store is total over its key space, and two groups do not share a counter.
func TestTheReserverIsTotalOverItsKeySpaceAndSeparatesGroups(t *testing.T) {
	fake := newStreamIndexMemory()
	for _, unseen := range [][]byte{nil, {}, {0x01}, []byte("a group nothing has written to")} {
		got, err := fake.HighWater(unseen)
		if err != nil {
			t.Errorf("HighWater of an unseen group answered %v; a group never seen is 0 with no error, so highWater + 1 is a well defined start", err)
		}
		if got != 0 {
			t.Errorf("HighWater of an unseen group is %d, want 0", got)
		}
	}
	left := []byte("group-left")
	right := []byte("group-right")
	for index := uint64(1); index <= 4; index += 1 {
		if err := fake.Reserve(left, index); err != nil {
			t.Fatalf("reserve %d for the left group: %v", index, err)
		}
	}
	if got, _ := fake.HighWater(right); got != 0 {
		t.Errorf("the right group's high water is %d after four reservations against the left group; the counter is per group and a shared one burns indices in one and re-issues them in the other", got)
	}
	if err := fake.Reserve(right, 1); err != nil {
		t.Errorf("index 1 was refused for a group that has never used it: %v", err)
	}
	if got, _ := fake.HighWater(left); got != 4 {
		t.Errorf("the left group's high water is %d after a reservation against the right group, want 4", got)
	}
}

// The layering refusal, asserted rather than stated: nothing in this package's PRODUCTION source
// implements StreamIndexReserver.
//
// The class is derived from the interface's own method set rather than from a list of file names:
// any production declaration -- a type with both methods, or a function returning something that
// has them -- is a durable store this package has grown, and section 8.2 says the durable store
// is sdk's. imports_test.go holds the other half, over the production import set, because a store
// needs an I/O package before it needs a method name.
func TestNoProductionDeclarationOfThisPackageImplementsTheReserver(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	// the method set is read off the interface's own declaration, so a method added to
	// StreamIndexReserver widens this gate with nobody remembering to
	wanted := streamIndexReserverMethodNames(t, sources)
	if len(wanted) == 0 {
		t.Fatal("StreamIndexReserver declares no method in this package's source, so this gate looked for nothing")
	}
	methods := map[string]map[string]bool{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv == nil || len(function.Recv.List) == 0 {
				continue
			}
			receiver := recordKeyReceiverTypeName(function.Recv.List[0].Type)
			if receiver == "" {
				continue
			}
			if methods[receiver] == nil {
				methods[receiver] = map[string]bool{}
			}
			methods[receiver][function.Name.Name] = true
		}
	}
	for receiver, has := range methods {
		complete := true
		for _, method := range wanted {
			if !has[method] {
				complete = false
				break
			}
		}
		if complete {
			t.Errorf("%s implements StreamIndexReserver in this package's production source; the durable store is section 8.2's MessageStore and a second one here is the second implementation of one thing",
				receiver)
		}
	}
}

func streamIndexReserverMethodNames(t *testing.T, sources []messagegroupSource) []string {
	t.Helper()
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral {
				continue
			}
			for _, spec := range general.Specs {
				typed, isTyped := spec.(*ast.TypeSpec)
				if !isTyped || typed.Name.Name != "StreamIndexReserver" {
					continue
				}
				declared, isInterface := typed.Type.(*ast.InterfaceType)
				if !isInterface || declared.Methods == nil {
					t.Fatal("StreamIndexReserver is declared and is not an interface")
				}
				names := []string{}
				for _, method := range declared.Methods.List {
					for _, name := range method.Names {
						names = append(names, name.Name)
					}
				}
				slices.Sort(names)
				return names
			}
		}
	}
	t.Fatal("this package declares no StreamIndexReserver")
	return nil
}

// The name a receiver expression hangs off, so a pointer receiver and a value receiver are one
// type.
func recordKeyReceiverTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return recordKeyReceiverTypeName(typed.X)
	case *ast.IndexExpr:
		return recordKeyReceiverTypeName(typed.X)
	}
	return ""
}
