// Reading the urmessage_leaf_keys leaf node extension off a leaf, MASTER section 5.3 and
// spec A section 3.4.
//
// The extension type, its struct, its codec and the two range checks on it all belong to the
// leaf node file family, because LeafNode.Validate is what holds a leaf's X-Wing key to
// XwingPublicKeyLen and it has to do that in the same wave the leaf lands in. What is here is
// only the group lifecycle's accessor, and nothing else belongs here: a second alg_id check or
// a second length check written beside this call is the drift extension.go's own briefing warns
// about, since a length check written against a different constant is how two constants come
// to disagree.
//
// A member with no X-Wing key cannot receive the epoch wrap, which is why 0xF002 is in this
// profile's required_capabilities and why absence is an error here rather than a nil result.
package mls

import "fmt"

// LeafKeysOf extracts and parses the urmessage_leaf_keys extension of a leaf node.
//
// The lookup is by extension TYPE and the entry it finds is handed to ParseLeafKeysFrom whole,
// which is the documented path on LeafKeysExtension and not an ornament on it. ParseLeafKeysFrom
// is the only entry point of that pair that is given the tag, so it is the only one that can
// refuse a body arriving under somebody else's; handing it the entry rather than the entry's
// body means the tag this accessor selected on and the tag the parse is held to are the same
// value, checked twice, rather than one value trusted once. An accessor that read
// leaf.Extensions[0] would answer a wrap target out of whatever extension happened to sit in
// that slot, and a commit secret wrapped to it goes to nobody.
//
// A leaf carrying urmessage_leaf_keys TWICE is refused rather than answered from, and the
// reason is that nothing else in this build refuses it. RFC 9420 forbids a repeated extension
// type; the comment that used to stand here, and the one on FindExtension, both handed that
// refusal to ValSem209 at whole leaf validation -- and ValSem209 is not implemented anywhere in
// this package. LeafNode.Validate walks every entry and range checks every urmessage_leaf_keys
// body it finds, which is a stronger check than a lookup would make and is still not a refusal
// of the repeat: a leaf carrying two well formed entries passes it.
//
// So this accessor was the only reader of a two entry leaf, and an accessor that answers one of
// two picks the group's wrap target by iteration order. That choice was not observable -- the
// walk was reversed and the whole suite passed -- and the two entries name two different
// devices, so half a group could wrap to one and half to the other with neither half able to
// tell. Refusing is the only answer with no arbitrary half in it, and it is also what makes the
// walk direction stop mattering: at most one entry of this type reaches the parse, so first and
// last are the same entry.
//
// Absence is a refusal rather than a nil result, because every v1 leaf carries one and a caller
// that treats "no wrap key" as a normal case is a caller that silently drops a member out of
// the epoch wrap -- which is not observable at the commit that did it, only at the first
// message that member cannot read.
//
// Both refusals carry ErrMalformedExtension, which is what the group lifecycle asks this
// question with, and the parse failure carries the codec's own ErrLeafKeysExtensionInvalid
// underneath it as well: the two name different repairs -- a leaf with no extension at all
// versus a leaf whose extension this profile cannot act on -- and joining them keeps both
// reachable through errors.Is from one result.
func LeafKeysOf(leaf *LeafNode) (*LeafKeysExtension, error) {
	if leaf == nil {
		return nil, fmt.Errorf("%w: nil leaf", ErrMalformedExtension)
	}
	// the whole vector is walked before anything is parsed, because the refusal is about the
	// vector rather than about either entry: a scan that returned at the first match cannot see
	// the second, so it cannot refuse the pair.
	found := -1
	for i := range leaf.Extensions {
		if leaf.Extensions[i].ExtensionType != ExtensionTypeUrmessageLeafKeys {
			continue
		}
		if found >= 0 {
			return nil, fmt.Errorf("%w: leaf carries urmessage_leaf_keys at entry %d and again at entry %d",
				ErrMalformedExtension, found, i)
		}
		found = i
	}
	if found < 0 {
		return nil, fmt.Errorf("%w: leaf carries no urmessage_leaf_keys extension", ErrMalformedExtension)
	}
	keys, err := ParseLeafKeysFrom(leaf.Extensions[found])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedExtension, err)
	}
	return keys, nil
}
