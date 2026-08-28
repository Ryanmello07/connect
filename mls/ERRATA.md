# RFC 9420 errata this package acts on

What this file is for: an implementation of a published RFC has to decide, one erratum at a
time, whether it follows the text as published or the text as corrected. That decision is not
visible from the code — a validator that applies a corrected rule looks exactly like one that
applies an invented rule — so each entry below records the erratum **verbatim**, the status it
carried when it was transcribed, the date it was read off the errata page, and what this package
does about it.

Two rules for anything added here.

- **Quote, do not summarise.** The transcription is what a later reader checks the code against.
  A paraphrase, or an entry that says "per the plan", is worth nothing: it cannot be diffed
  against <https://errata.rfc-editor.org/rfc9420> and it hides whichever detail the paraphraser
  did not think mattered.
- **Record the status, and record that the status can change.** An erratum in `Reported` has been
  submitted and nothing more. It has not been accepted by the responsible Area Director, it is
  not `Verified`, and it is not `Held for Document Update`. Implementing one is a decision to
  diverge from the published RFC, and the divergence has to be stated as such rather than as
  "the RFC says".

This file records only errata this package has **acted on**. An erratum absent from it has not
been assessed here.

---

## Erratum 8745 — Section 13.4, LeafNode capabilities in Update proposals and update paths

Retrieved from <https://errata.rfc-editor.org/eid8745> on **2026-08-28**.

| | |
|---|---|
| Errata ID | 8745 |
| RFC | 9420, "The Messaging Layer Security (MLS) Protocol", July 2023 |
| Source of RFC | mls (sec) |
| Section | 13.4 |
| Status | **Reported** |
| Type | Technical |
| Publication Format | TXT |
| Reported By | Jan Winkelmann |
| Date Reported | 2026-02-05 |

### Section 13.4 says

```
   *  A client adding a new member to a group MUST verify that the
      LeafNode for the new member is compatible with the group's
      extensions.  The capabilities field MUST indicate support for each
      extension in the GroupContext.
```

### It should say

```
   *  A client adding a new member to a group MUST verify that the
      LeafNode for the new member is compatible with the group's
      extensions.  The capabilities field MUST indicate support for each
      extension in the GroupContext.

   *  A client updating a leaf node in the group MUST verify that the
      new LeafNode is compatible with the group's extensions.  The
      capabilities field MUST indicate support for each extension in the
      GroupContext. This applies both to Update proposals and LeafNode
      objects in the update_path in a Commit.
```

### Notes

```
The RFC says on the topic of validating LeafNode capabilities:
> Note that the latter two requirements mean that all
> MLS GroupContext extensions are mandatory, in the
> sense that an extension in use by the group MUST be
> supported by all members of the group.
> --- https://www.rfc-editor.org/rfc/rfc9420.html#section-13.4-6
To that end, it requires that we check that the LeafNodes in KeyPackages
that are added support all extensions in the group context. However, it
doesn't seem to require that the same check is performed for LeafNodes in
Update proposals or update paths.
Also see this thread on the mailing list: https://mailarchive.ietf.org/arch/msg/mls/k18P4FP7dfS2cBmP0kL6Uh50-ok/
```

### The "Section 13.4 says" quotation was checked against the RFC

The four lines the erratum quotes are the fifth bullet of RFC 9420 section 13.4's list of things
"implementations MUST correctly handle", and they are reproduced exactly. The paragraph the
Notes quote — "Note that the latter two requirements mean that all MLS GroupContext extensions
are mandatory, in the sense that an extension in use by the group MUST be supported by all
members of the group" — follows two bullets later in the same section. Neither is misquoted, and
the inconsistency the erratum describes is present in the published text: section 13.4 imposes
the group-extension compatibility check on the client *adding* a member and on the client
*joining*, and on nobody else, while asserting a conclusion about *all members of the group*.

### What this package does

`(*LeafNode).Validate` in `leaf_node.go` applies the group-extension check to **all three**
leaf_node_source values — `key_package`, `update` and `commit` — and the loop that does it is
not conditioned on the source. `TestErrata8745` states both halves over the derived source class:
a leaf that does not list a non-default GroupContext extension is refused under every source, and
a leaf that does list it is accepted under every source. An implementation written from the
uncorrected text passes the `key_package` row and fails the other two.

**This is stricter than the published RFC, deliberately, and the erratum is only `Reported`.**
The consequences are worth being explicit about, because a reader who finds this later should not
have to re-derive them:

- Security: without the correction, a member already in the group can send an Update proposal, or
  a Commit carrying an update_path, whose new LeafNode drops support for an extension the group
  is using. Nothing in the published text refuses it, and the group is then in the state section
  13.4 says cannot happen — an extension in use that not every member supports.
- Interoperability: a peer implementing the published text may send exactly such an Update. This
  package refuses it, and the refusal is `errMissingRequiredCapability`. That is a real
  divergence and not a bug in the peer.
- Status: `Reported` means submitted. If the erratum is later **Rejected**, the strictness above
  becomes a divergence with no standing behind it and this entry — and the loop in
  `leaf_node.go` — should be revisited. Re-read the status at the URL above rather than trusting
  this table, which is a snapshot of one day.

### Where this package does NOT follow the erratum's literal wording

The erratum says "The capabilities field MUST indicate support for each extension in the
GroupContext", repeating the published sentence. Taken with no exemption, that sentence refuses
every conforming leaf of any group whose GroupContext carries `required_capabilities` (0x0003) or
`external_senders`, because RFC 9420 section 7.2 says of the same `capabilities.extensions`
vector:

```
   The capabilities field indicates the protocol features that the
   client supports, including protocol versions, cipher suites,
   credential types, non-default proposal types, and non-default
   extension types.  The following proposal and extension types are
   considered "default" and MUST NOT be listed:
   ...
   *  Extension types:

      -  0x0001 - application_id

      -  0x0002 - ratchet_tree

      -  0x0003 - required_capabilities

      -  0x0004 - external_pub

      -  0x0005 - external_senders
```

Both sentences are MUSTs and they cannot both be obeyed for a default type. This package resolves
it the only way that leaves neither sentence violated: the five default types are exempt from the
section 13.4 check, because section 11.1 says they "are assumed to be implemented by all clients,
and need not be listed in RequiredCapabilities in order to be safely used" — that is, section
13.4's requirement is already discharged for them. `isDefaultExtensionType` in `leaf_node.go`
derives that class as the contiguous range 0x0001..0x0005, which is exactly RFC 9420's own
initial extension registry (section 17.3), and
`TestTheDefaultExtensionTypeClassIsExactlyTheFiveRfc9420Section72Names` holds the range against
the five code points over the whole uint16 space. A code point registered by a later document is
**not** default and must be listed.
