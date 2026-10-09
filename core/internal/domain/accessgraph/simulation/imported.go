package simulation

import (
	"crypto/sha256"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
)

func proposedImportedInputsCurrent(candidate publication.Candidate, vector accessgraph.RevisionVector) bool {
	for _, value := range candidate.ImportedResourceDestinations() {
		if value.Resolution().ConsumerSharingRevision() != vector.SharingRevision() {
			return false
		}
	}
	return true
}

func importedIntentChanges(current, proposed []publication.ImportedResourceDestination) (
	[]publication.ImportedResourceDestination, []publication.ImportedResourceDestination,
) {
	currentByID := make(map[policy.RuleID][sha256.Size]byte, len(current))
	proposedByID := make(map[policy.RuleID][sha256.Size]byte, len(proposed))
	for _, value := range current {
		currentByID[value.RuleID()] = importedIntentHash(value)
	}
	for _, value := range proposed {
		proposedByID[value.RuleID()] = importedIntentHash(value)
	}
	added := make([]publication.ImportedResourceDestination, 0)
	removed := make([]publication.ImportedResourceDestination, 0)
	for _, value := range proposed {
		if previous, found := currentByID[value.RuleID()]; !found || previous != proposedByID[value.RuleID()] {
			added = append(added, value)
		}
	}
	for _, value := range current {
		if next, found := proposedByID[value.RuleID()]; !found || next != currentByID[value.RuleID()] {
			removed = append(removed, value)
		}
	}
	compare := func(first, second publication.ImportedResourceDestination) int {
		return strings.Compare(first.RuleID().String(), second.RuleID().String())
	}
	slices.SortFunc(added, compare)
	slices.SortFunc(removed, compare)
	return added, removed
}

func validImportedIntents(values []publication.ImportedResourceDestination, scope network.Scope) bool {
	for index, value := range values {
		if !value.IsValid() || value.Resolution().ConsumerScope() != scope ||
			index > 0 && values[index-1].RuleID().String() >= value.RuleID().String() {
			return false
		}
	}
	return values != nil
}

func importedIntentHash(value publication.ImportedResourceDestination) [sha256.Size]byte {
	encoder := impactEncoder{digest: sha256.New()}
	encoder.write([]byte("meshtransit/policy-simulation-imported-intent/v1\x00"))
	encoder.writeImportedIntent(value)
	var digest [sha256.Size]byte
	copy(digest[:], encoder.digest.Sum(nil))
	return digest
}

func (encoder impactEncoder) writeImportedIntents(values []publication.ImportedResourceDestination) {
	encoder.writeUint64(uint64(len(values)))
	for _, value := range values {
		encoder.writeImportedIntent(value)
	}
}

func (encoder impactEncoder) writeImportedIntent(value publication.ImportedResourceDestination) {
	resolution := value.Resolution()
	contract := resolution.Contract()
	resource := contract.Resource()
	encoder.writeText(value.RuleID().String())
	encoder.writeText(value.SourceNodeID().String())
	encoder.write([]byte{byte(value.Protocol())})
	ports := value.DestinationPortRanges()
	encoder.writeUint64(uint64(len(ports)))
	for _, port := range ports {
		encoder.writeUint16(port.First())
		encoder.writeUint16(port.Last())
	}
	for _, id := range [...]string{
		resolution.ImportedResourceID().String(), contract.ID().String(), contract.OfferID().String(),
		contract.ExportID().String(), resolution.ProviderScope().WorkspaceID().String(),
		resolution.ProviderScope().NetworkID().String(), resolution.ConsumerScope().WorkspaceID().String(),
		resolution.ConsumerScope().NetworkID().String(), resource.ResourceID().String(),
	} {
		encoder.writeText(id)
	}
	for _, version := range [...]int64{
		resolution.ImportedResourceVersion(), contract.Version(), resolution.ExportVersion(),
		resource.ResourceVersion(), resource.TargetGeneration(), resolution.ProviderInventoryRevision(),
		resolution.ProviderSharingRevision(), resolution.ConsumerSharingRevision(),
		contract.ProviderAuthorityGeneration(), contract.ConsumerAuthorityGeneration(), contract.RecoveryEpoch(),
	} {
		encoder.writeInt64(version)
	}
	resourceHash := resource.SemanticHash().Bytes()
	encoder.write(resourceHash[:])
	trafficHash := contract.MaximumTraffic().Hash()
	encoder.write(trafficHash[:])
	encoder.writeText(contract.ExpiresAt().UTC().Format(time.RFC3339Nano))
}
