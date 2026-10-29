package kubecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
)

// policyHash is a policy's fingerprint over what it does and what it
// covers: validations, conditions, variables, audit annotations and every
// match constraint (review c2b H4, M-a), with the API server's defaults
// taken out (normalized). The chart computes the same over what it
// renders, so an edit in place shows.
func policyHash(spec map[string]any) (string, error) {
	return fingerprint(map[string]any{
		"validations": spec["validations"], "matchConditions": spec["matchConditions"],
		"variables": spec["variables"], "auditAnnotations": spec["auditAnnotations"],
		"matchConstraints": normalized(spec["matchConstraints"]),
	})
}

// bindingHash is a binding's fingerprint over its policy, actions,
// parameters and everything that chooses what it covers.
func bindingHash(spec map[string]any) (string, error) {
	return fingerprint(map[string]any{
		"policyName": spec["policyName"], "validationActions": spec["validationActions"],
		"paramRef": spec["paramRef"], "matchResources": normalized(spec["matchResources"]),
	})
}

// normalized takes the API server's defaults out of match constraints or
// resources: matchPolicy Equivalent, empty selectors, a rule's "*" scope;
// what is left empty counts as absent.
func normalized(value any) any {
	match, ok := value.(map[string]any)
	if !ok {
		return value
	}
	cleaned := map[string]any{}
	for key, item := range match {
		switch {
		case key == "matchPolicy" && item == "Equivalent":
		case (key == "namespaceSelector" || key == "objectSelector") && isEmpty(item):
		case key == "resourceRules" || key == "excludeResourceRules":
			rules, isList := item.([]any)
			if !isList {
				cleaned[key] = item
				continue
			}
			kept := make([]any, 0, len(rules))
			for _, rule := range rules {
				fields, isMap := rule.(map[string]any)
				if !isMap {
					kept = append(kept, rule)
					continue
				}
				copied := map[string]any{}
				for name, field := range fields {
					if name != "scope" || field != "*" {
						copied[name] = field
					}
				}
				kept = append(kept, copied)
			}
			if len(kept) > 0 {
				cleaned[key] = kept
			}
		default:
			cleaned[key] = item
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

func isEmpty(value any) bool {
	fields, ok := value.(map[string]any)
	return value == nil || (ok && len(fields) == 0)
}

// fingerprint is the SHA-256 of value's JSON, as Helm's toJson writes it
// (encoding/json: sorted keys, HTML-escaped).
func fingerprint(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// forbidden reports the API server refusing the check's own account.
func forbidden(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && (status.Code == http.StatusForbidden || status.Code == http.StatusUnauthorized)
}

// unreadable reports a read that failed: refused (the chart's Role is not
// what the check needs, a failure) or for a reason that may pass (a warning).
func (checker Checker) unreadable(report *Report, what string, err error) {
	if forbidden(err) {
		report.add(Fail, "check_forbidden", "%s: the check may not read it: %v", what, err)
		return
	}
	report.add(Warn, "check_unreadable", "%s: %v", what, err)
}
