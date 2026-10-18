package netadmin

import (
	"net/netip"

	"meshtransit.net/client/internal/overlayframe"
)

// SafeOverlayFrame returns the fixed outer bound for helper allowlists
// (overlayframe). It is also the allowlist meshnetd uses when none is
// configured.
func SafeOverlayFrame() []netip.Prefix { return overlayframe.Prefixes() }

// WithinSafeOverlayFrame reports whether prefix lies wholly inside the safe
// overlay frame; Windows, which has no privileged helper, checks it in meshd.
func WithinSafeOverlayFrame(prefix netip.Prefix) bool { return overlayframe.Contains(prefix) }

// withinSafeOverlayFrame reports whether prefix lies wholly inside one frame
// prefix. An allowlist may narrow the frame, never widen it.
func withinSafeOverlayFrame(prefix netip.Prefix) bool { return overlayframe.Contains(prefix) }
