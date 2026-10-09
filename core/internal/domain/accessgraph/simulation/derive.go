package simulation

import (
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
)

type relationshipKey struct {
	source      node.ID
	destination node.ID
	protocol    policy.Protocol
}

type explanationKey struct {
	ruleID      policy.RuleID
	destination node.ID
}

func newResult(baseline Baseline, proposed publication.Candidate) (Result, error) {
	if !baseline.IsValid() || !proposed.IsValid() ||
		proposed.Snapshot().Scope() != baseline.scope {
		return Result{}, ErrInvalidResult
	}
	proposedVector, err := baseline.revisionVector.NextPolicy()
	if err != nil || proposed.Snapshot().Revision() != proposedVector.PolicyRevision() ||
		!candidateInputsWithin(proposed, baseline.revisionVector) ||
		!candidateInputsWithin(baseline.candidate, baseline.revisionVector) ||
		!proposedImportedInputsCurrent(proposed, baseline.revisionVector) {
		return Result{}, ErrInvalidResult
	}

	currentRules, err := resolvedRules(baseline.candidate, baseline.selectorMembers)
	if err != nil {
		return Result{}, err
	}
	proposedRules, err := resolvedRules(proposed, baseline.selectorMembers)
	if err != nil {
		return Result{}, err
	}
	currentRelationships, err := effectiveRelationships(currentRules)
	if err != nil {
		return Result{}, err
	}
	proposedRelationships, err := effectiveRelationships(proposedRules)
	if err != nil {
		return Result{}, err
	}
	currentExplanations, err := explanations(baseline.candidate, currentRules)
	if err != nil {
		return Result{}, err
	}
	proposedExplanations, err := explanations(proposed, proposedRules)
	if err != nil {
		return Result{}, err
	}
	addedRelationships, removedRelationships, err := relationshipChanges(
		currentRelationships,
		proposedRelationships,
	)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		baseline: baseline, proposedCandidate: proposed, proposedVector: proposedVector,
		addedRelationships:   addedRelationships,
		removedRelationships: removedRelationships,
		addedExplanations: difference(
			proposedExplanations,
			currentExplanations,
			compareExplanations,
		),
		removedExplanations: difference(
			currentExplanations,
			proposedExplanations,
			compareExplanations,
		),
		unsupported: []UnsupportedCapability{
			UnsupportedCapabilityPrincipalProjection,
			UnsupportedCapabilitySensitiveResourceClassification,
			UnsupportedCapabilityCrossScopeRelationships,
			UnsupportedCapabilityGuardrailEvaluation,
			UnsupportedCapabilityShareIntersection,
			UnsupportedCapabilityRoutedServiceResources,
		},
	}
	result.addedImportedIntents, result.removedImportedIntents = importedIntentChanges(
		baseline.candidate.ImportedResourceDestinations(), proposed.ImportedResourceDestinations(),
	)
	result.affectedDevices, result.affectedResources, result.affectedGroups = affectedEntities(result)
	result.hash = hashResult(result)
	if !result.IsValid() {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

func candidateInputsWithin(
	candidate publication.Candidate,
	vector accessgraph.RevisionVector,
) bool {
	for _, destination := range candidate.ResourceDestinations() {
		if destination.InventoryRevision() > vector.InventoryRevision() {
			return false
		}
	}
	for _, destination := range candidate.ResourceGroupDestinations() {
		if destination.GroupRevision() > vector.GroupRevision() {
			return false
		}
		for _, member := range destination.Members() {
			if member.InventoryRevision() > vector.InventoryRevision() {
				return false
			}
		}
	}
	for _, destination := range candidate.ImportedResourceDestinations() {
		if destination.Resolution().ConsumerSharingRevision() > vector.SharingRevision() {
			return false
		}
	}
	return true
}

// resolvedRules is the candidate's Device pairs plus its group rules
// resolved from the baseline membership. A group the baseline does not know
// changed since the baseline was read.
func resolvedRules(candidate publication.Candidate, members map[publication.RuleSide][]node.ID) ([]policy.Rule, error) {
	rules := candidate.Snapshot().Rules()
	scope := candidate.Snapshot().Scope()
	// A selector with no live Device is absent from members: it selects none.
	side := func(selected publication.RuleSide) []node.ID {
		if selected.Kind() == publication.SideDevice {
			return []node.ID{node.ID(selected.ID())}
		}
		return members[selected]
	}
	for _, groupRule := range candidate.GroupRules() {
		sources := side(groupRule.Source())
		destinations := side(groupRule.Destination())
		if len(rules)+len(sources)*len(destinations) > MaximumResolvedRelationships {
			return nil, ErrTooLarge
		}
		for _, source := range sources {
			for _, destination := range destinations {
				if source == destination {
					continue
				}
				rule, err := policy.NewRule(policy.RuleParams{
					ID: groupRule.RuleID(), Scope: scope, SourceNodeID: source, DestinationNodeID: destination,
					Protocol: groupRule.Protocol(), DestinationPortRanges: groupRule.DestinationPortRanges(),
				})
				if err != nil {
					return nil, ErrInvalidResult
				}
				rules = append(rules, rule)
			}
		}
	}
	return rules, nil
}

func effectiveRelationships(rules []policy.Rule) ([]Relationship, error) {
	byKey := make(map[relationshipKey][]policy.PortRange)
	for _, rule := range rules {
		key := relationshipKey{
			source: rule.SourceNodeID(), destination: rule.DestinationNodeID(), protocol: rule.Protocol(),
		}
		if _, found := byKey[key]; !found {
			byKey[key] = []policy.PortRange{}
		}
		byKey[key] = append(byKey[key], rule.DestinationPortRanges()...)
	}
	keys := make([]relationshipKey, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareRelationshipKeys)
	values := make([]Relationship, 0, len(rules))
	for _, key := range keys {
		if key.protocol == policy.ProtocolICMP {
			value, err := newRelationship(key.source, key.destination, key.protocol, 0, 0)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
			continue
		}
		for _, portRange := range mergePortRanges(byKey[key]) {
			value, err := newRelationship(
				key.source,
				key.destination,
				key.protocol,
				portRange.First(),
				portRange.Last(),
			)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
	}
	return values, nil
}

func compareRelationshipKeys(first, second relationshipKey) int {
	if comparison := strings.Compare(first.source.String(), second.source.String()); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(first.destination.String(), second.destination.String()); comparison != 0 {
		return comparison
	}
	return int(first.protocol) - int(second.protocol)
}

func mergePortRanges(values []policy.PortRange) []policy.PortRange {
	values = slices.Clone(values)
	slices.SortFunc(values, func(first, second policy.PortRange) int {
		if first.First() != second.First() {
			return int(first.First()) - int(second.First())
		}
		return int(first.Last()) - int(second.Last())
	})
	merged := make([]policy.PortRange, 0, len(values))
	for _, value := range values {
		if len(merged) == 0 {
			merged = append(merged, value)
			continue
		}
		previous := merged[len(merged)-1]
		adjacent := previous.Last() != ^uint16(0) && value.First() == previous.Last()+1
		if value.First() > previous.Last() && !adjacent {
			merged = append(merged, value)
			continue
		}
		if value.Last() > previous.Last() {
			merged[len(merged)-1], _ = policy.NewPortRange(previous.First(), value.Last())
		}
	}
	return merged
}

func relationshipChanges(
	current,
	proposed []Relationship,
) ([]Relationship, []Relationship, error) {
	currentByKey := relationshipsByKey(current)
	proposedByKey := relationshipsByKey(proposed)
	keys := make([]relationshipKey, 0, len(currentByKey)+len(proposedByKey))
	seen := make(map[relationshipKey]struct{}, len(currentByKey)+len(proposedByKey))
	for key := range currentByKey {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range proposedByKey {
		if _, found := seen[key]; !found {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, compareRelationshipKeys)
	added := make([]Relationship, 0)
	removed := make([]Relationship, 0)
	for _, key := range keys {
		currentRanges, hasCurrent := currentByKey[key]
		proposedRanges, hasProposed := proposedByKey[key]
		if key.protocol == policy.ProtocolICMP {
			switch {
			case hasProposed && !hasCurrent:
				value, err := newRelationship(key.source, key.destination, key.protocol, 0, 0)
				if err != nil {
					return nil, nil, err
				}
				added = append(added, value)
			case hasCurrent && !hasProposed:
				value, err := newRelationship(key.source, key.destination, key.protocol, 0, 0)
				if err != nil {
					return nil, nil, err
				}
				removed = append(removed, value)
			}
			continue
		}
		addedRanges := subtractPortRanges(proposedRanges, currentRanges)
		removedRanges := subtractPortRanges(currentRanges, proposedRanges)
		for _, portRange := range addedRanges {
			value, err := newRelationship(
				key.source,
				key.destination,
				key.protocol,
				portRange.First(),
				portRange.Last(),
			)
			if err != nil {
				return nil, nil, err
			}
			added = append(added, value)
		}
		for _, portRange := range removedRanges {
			value, err := newRelationship(
				key.source,
				key.destination,
				key.protocol,
				portRange.First(),
				portRange.Last(),
			)
			if err != nil {
				return nil, nil, err
			}
			removed = append(removed, value)
		}
	}
	return added, removed, nil
}

func relationshipsByKey(values []Relationship) map[relationshipKey][]policy.PortRange {
	byKey := make(map[relationshipKey][]policy.PortRange)
	for _, value := range values {
		key := relationshipKey{
			source: value.sourceNodeID, destination: value.destinationNodeID, protocol: value.protocol,
		}
		if _, found := byKey[key]; !found {
			byKey[key] = []policy.PortRange{}
		}
		if value.protocol != policy.ProtocolICMP {
			portRange, _ := policy.NewPortRange(value.firstPort, value.lastPort)
			byKey[key] = append(byKey[key], portRange)
		}
	}
	return byKey
}

func subtractPortRanges(source, excluded []policy.PortRange) []policy.PortRange {
	remaining := make([]policy.PortRange, 0, len(source))
	for _, sourceRange := range source {
		cursor := sourceRange.First()
		last := sourceRange.Last()
		fullyExcluded := false
		for _, excludedRange := range excluded {
			excludedFirst := excludedRange.First()
			excludedLast := excludedRange.Last()
			if excludedLast < cursor {
				continue
			}
			if excludedFirst > last {
				break
			}
			if excludedFirst > cursor {
				value, _ := policy.NewPortRange(cursor, excludedFirst-1)
				remaining = append(remaining, value)
			}
			if excludedLast >= last {
				fullyExcluded = true
				break
			}
			cursor = excludedLast + 1
		}
		if !fullyExcluded && cursor <= last {
			value, _ := policy.NewPortRange(cursor, last)
			remaining = append(remaining, value)
		}
	}
	return remaining
}

func explanations(candidate publication.Candidate, rules []policy.Rule) ([]Explanation, error) {
	direct := make(map[policy.RuleID]publication.ResourceDestination)
	for _, destination := range candidate.ResourceDestinations() {
		direct[destination.RuleID()] = destination
	}
	group := make(map[explanationKey]groupMemberEvidence)
	for _, destination := range candidate.ResourceGroupDestinations() {
		for _, member := range destination.Members() {
			group[explanationKey{
				ruleID: destination.RuleID(), destination: member.DestinationNodeID(),
			}] = groupMemberEvidence{group: destination, member: member}
		}
	}
	values := make([]Explanation, 0, len(rules))
	for _, rule := range rules {
		value := Explanation{
			scope: rule.Scope(), ruleID: rule.ID(), sourceNodeID: rule.SourceNodeID(),
			destinationNodeID: rule.DestinationNodeID(), protocol: rule.Protocol(),
			destinationPortRanges: rule.DestinationPortRanges(),
			selectorKind:          accessgraph.SelectorKindDevice,
		}
		if destination, found := direct[rule.ID()]; found {
			reference := destination.Reference()
			value.selectorKind = accessgraph.SelectorKindResource
			value.resourceID = reference.ResourceID()
			value.resourceVersion = reference.ResourceVersion()
			value.targetGeneration = reference.TargetGeneration()
			value.inventoryRevision = destination.InventoryRevision()
			value.resourceSemanticHash = destination.ResourceSemanticHash()
		} else if evidence, found := group[explanationKey{
			ruleID: rule.ID(), destination: rule.DestinationNodeID(),
		}]; found {
			reference := evidence.member.Reference()
			value.selectorKind = accessgraph.SelectorKindResourceGroup
			value.resourceID = reference.ResourceID()
			value.resourceVersion = reference.ResourceVersion()
			value.targetGeneration = reference.TargetGeneration()
			value.inventoryRevision = evidence.member.InventoryRevision()
			value.resourceSemanticHash = evidence.member.ResourceSemanticHash()
			value.groupID = evidence.group.ResourceGroupID()
			value.groupVersion = evidence.group.GroupVersion()
			value.definitionVersion = evidence.group.DefinitionVersion()
			value.groupRevision = evidence.group.GroupRevision()
			value.groupSemanticHash = evidence.group.GroupSemanticHash()
		}
		if !value.IsValid() {
			return nil, ErrInvalidResult
		}
		values = append(values, value)
	}
	slices.SortFunc(values, compareExplanations)
	return values, nil
}

type groupMemberEvidence struct {
	group  publication.ResourceGroupDestination
	member publication.ResourceGroupMemberDestination
}

func affectedEntities(result Result) ([]node.ID, []resource.ID, []resource.GroupID) {
	devices := make(map[node.ID]struct{})
	resources := make(map[resource.ID]struct{})
	groups := make(map[resource.GroupID]struct{})
	for _, values := range [][]Relationship{result.addedRelationships, result.removedRelationships} {
		for _, relationship := range values {
			devices[relationship.sourceNodeID] = struct{}{}
			devices[relationship.destinationNodeID] = struct{}{}
		}
	}
	for _, values := range [][]Explanation{result.addedExplanations, result.removedExplanations} {
		for _, explanation := range values {
			devices[explanation.sourceNodeID] = struct{}{}
			devices[explanation.destinationNodeID] = struct{}{}
			if explanation.resourceID.IsValid() {
				resources[explanation.resourceID] = struct{}{}
			}
			if explanation.groupID.IsValid() {
				groups[explanation.groupID] = struct{}{}
			}
		}
	}
	deviceIDs := make([]node.ID, 0, len(devices))
	for _, values := range [][]publication.ImportedResourceDestination{
		result.addedImportedIntents, result.removedImportedIntents,
	} {
		for _, value := range values {
			devices[value.SourceNodeID()] = struct{}{}
		}
	}
	for id := range devices {
		deviceIDs = append(deviceIDs, id)
	}
	resourceIDs := make([]resource.ID, 0, len(resources))
	for id := range resources {
		resourceIDs = append(resourceIDs, id)
	}
	groupIDs := make([]resource.GroupID, 0, len(groups))
	for id := range groups {
		groupIDs = append(groupIDs, id)
	}
	slices.SortFunc(deviceIDs, func(first, second node.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	slices.SortFunc(resourceIDs, func(first, second resource.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	slices.SortFunc(groupIDs, func(first, second resource.GroupID) int {
		return strings.Compare(first.String(), second.String())
	})
	return deviceIDs, resourceIDs, groupIDs
}

func difference[T any](first, second []T, compare func(T, T) int) []T {
	values := make([]T, 0)
	firstIndex, secondIndex := 0, 0
	for firstIndex < len(first) {
		if secondIndex >= len(second) {
			values = append(values, first[firstIndex:]...)
			break
		}
		switch comparison := compare(first[firstIndex], second[secondIndex]); {
		case comparison < 0:
			values = append(values, first[firstIndex])
			firstIndex++
		case comparison > 0:
			secondIndex++
		default:
			firstIndex++
			secondIndex++
		}
	}
	return values
}
