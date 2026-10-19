package dataplane

import (
	"net/netip"
	"slices"
	"strings"
	"time"
)

// RoutedActivity is what this node sent to one Site and heard back: the
// evidence a consumer suspects its router with (design §6.3).
type RoutedActivity struct {
	Ref string
	// LastSent and LastAnswered are the last packet sent to the Site and the
	// last tracked reply from it.
	LastSent, LastAnswered time.Time
	// WaitingSince is the first packet sent since the last reply; zero when
	// every packet sent was answered.
	WaitingSince time.Time
}

// noteRoutedLocked records a packet to (sent) or a tracked reply from a
// Site's address.
func (f *policyFilter) noteRoutedLocked(address netip.Addr, sent bool, now time.Time) {
	_, site, found := f.routed.lookup(address)
	if !found {
		return
	}
	if f.routedActivity == nil {
		f.routedActivity = map[string]*RoutedActivity{}
	}
	activity := f.routedActivity[site.ref]
	if activity == nil {
		activity = &RoutedActivity{Ref: site.ref}
		f.routedActivity[site.ref] = activity
	}
	if sent {
		activity.LastSent = now
		if activity.WaitingSince.IsZero() {
			activity.WaitingSince = now
		}
		return
	}
	activity.LastAnswered, activity.WaitingSince = now, time.Time{}
}

// pruneRoutedActivityLocked forgets Sites the routed table no longer holds,
// so the activity kept is bounded by the map's Sites.
func (f *policyFilter) pruneRoutedActivityLocked() {
	if len(f.routedActivity) == 0 {
		return
	}
	kept := map[string]struct{}{}
	if f.routed != nil {
		for _, site := range f.routed.sites {
			kept[site.ref] = struct{}{}
		}
	}
	for ref := range f.routedActivity {
		if _, found := kept[ref]; !found {
			delete(f.routedActivity, ref)
		}
	}
}

// RoutedActivity returns each Site's activity, in reference order.
func (f *policyFilter) RoutedActivity() []RoutedActivity {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	activity := make([]RoutedActivity, 0, len(f.routedActivity))
	for _, site := range f.routedActivity {
		activity = append(activity, *site)
	}
	slices.SortFunc(activity, func(first, second RoutedActivity) int { return strings.Compare(first.Ref, second.Ref) })
	return activity
}

// RoutedActivity returns what this node sent to each Site and heard back.
func (e *WireGuardEngine) RoutedActivity() []RoutedActivity {
	if e == nil {
		return nil
	}
	return e.filter.RoutedActivity()
}
