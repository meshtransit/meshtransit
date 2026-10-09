package networkmap

import (
	"errors"

	"meshtransit.net/shared/policydigest"
)

// ErrPolicyDigest reports a rule the policy digest cannot represent.
var ErrPolicyDigest = errors.New("networkmap: policy digest")

// PolicyDigest returns the policy digest v1 of rules and how many distinct
// grants they cover (docs/protocol/policy-digest-v1.md).
func PolicyDigest(rules []Rule) (policydigest.Digest, int, error) {
	converted := make([]policydigest.Rule, 0, len(rules))
	for _, rule := range rules {
		next := policydigest.Rule{
			Sources:      make([]policydigest.Selector, 0, len(rule.Sources)),
			Destinations: make([]policydigest.Destination, 0, len(rule.Destinations)),
			Protocols:    rule.Protocols,
		}
		for _, source := range rule.Sources {
			selector, err := digestSelector(source)
			if err != nil {
				return policydigest.Digest{}, 0, err
			}
			next.Sources = append(next.Sources, selector)
		}
		for _, destination := range rule.Destinations {
			selector, err := digestSelector(destination.Selector)
			if err != nil {
				return policydigest.Digest{}, 0, err
			}
			next.Destinations = append(next.Destinations, policydigest.Destination{
				Selector: selector, PortFrom: destination.PortFrom, PortTo: destination.PortTo,
			})
		}
		converted = append(converted, next)
	}
	digest, grants, err := policydigest.Compute(converted)
	if err != nil {
		return policydigest.Digest{}, 0, errors.Join(ErrPolicyDigest, err)
	}
	return digest, grants, nil
}

func digestSelector(selector Selector) (policydigest.Selector, error) {
	switch selector.Kind {
	case SelectorAny:
		return policydigest.Selector{Kind: policydigest.KindAny}, nil
	case SelectorPrefix:
		return policydigest.Selector{Kind: policydigest.KindPrefix, Prefix: selector.Prefix}, nil
	case SelectorRange:
		return policydigest.Selector{Kind: policydigest.KindRange, RangeStart: selector.RangeStart,
			RangeEnd: selector.RangeEnd}, nil
	case SelectorCapability:
		return policydigest.Selector{Kind: policydigest.KindCapability, Capability: selector.Capability}, nil
	default:
		return policydigest.Selector{}, ErrPolicyDigest
	}
}
