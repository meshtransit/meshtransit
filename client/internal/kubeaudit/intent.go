package kubeaudit

import (
	"unicode"
	"unicode/utf8"

	"meshtransit.net/client/internal/controlplane"
)

// Bounds of an intent's fields, Core's (mtcp-v1 §6.10, K1b0 §3.2): an
// intent out of them is refused here, never sent (review b2 H1).
const (
	maximumGroups       = 16
	maximumGroup        = 63
	maximumVerb         = 32
	maximumAPIGroup     = 253
	maximumResource     = 63
	maximumNamespace    = 63
	maximumName         = 253
	maximumImpersonated = 253
	maximumTokenID      = 32
	maximumPeer         = 36
	// intentOverhead bounds an intent's encoding beyond its strings: tags,
	// lengths, its ID, class and time.
	intentOverhead = 128
	// batchBudget is the encoded size a batch is kept under, below the
	// message's 128 KiB.
	batchBudget = 120 << 10
)

// RefusedInvalid is the refusal of an intent out of bounds.
const RefusedInvalid = "invalid"

// validIntent reports an intent within Core's bounds: a known class, clean
// UTF-8 of the right lengths, without control, format or line separator
// characters.
func validIntent(intent controlplane.KubeAuditIntent) bool {
	switch intent.Class {
	case "write", "exec", "proxy", "secret_read", "privileged", "unparsed":
	default:
		return false // one would fail its whole batch
	}
	if len(intent.Groups) > maximumGroups || len(intent.TokenID) > maximumTokenID ||
		!clean(intent.Peer, 1, maximumPeer) {
		return false
	}
	for _, group := range intent.Groups {
		if !clean(group, 1, maximumGroup) {
			return false
		}
	}
	for _, field := range []struct {
		value         string
		minimum, most int
	}{
		{intent.Verb, 1, maximumVerb}, {intent.APIGroup, 0, maximumAPIGroup},
		{intent.Resource, 0, maximumResource}, {intent.Subresource, 0, maximumResource},
		{intent.Namespace, 0, maximumNamespace}, {intent.Name, 0, maximumName},
		{intent.Impersonated, 0, maximumImpersonated},
	} {
		if !clean(field.value, field.minimum, field.most) {
			return false
		}
	}
	return true
}

func clean(value string, minimum, most int) bool {
	if len(value) < minimum || len(value) > most || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// encodedSize bounds an intent's encoded size.
func encodedSize(intent controlplane.KubeAuditIntent) int {
	size := intentOverhead + len(intent.Peer) + len(intent.Verb) + len(intent.APIGroup) + len(intent.Resource) +
		len(intent.Subresource) + len(intent.Namespace) + len(intent.Name) + len(intent.Impersonated) +
		len(intent.TokenID)
	for _, group := range intent.Groups {
		size += len(group) + 2
	}
	return size
}
