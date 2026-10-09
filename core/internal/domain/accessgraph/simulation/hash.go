package simulation

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"meshtransit.net/core/internal/domain/accessgraph"
)

const impactHashDomainV1 = "meshtransit/policy-simulation-impact/v1\x00"
const impactHashDomainV2 = "meshtransit/policy-simulation-impact/v2\x00"

type impactEncoder struct{ digest hash.Hash }

func hashResult(result Result) ImpactHash {
	encoder := impactEncoder{digest: sha256.New()}
	imported := result.baseline.candidate.CompilerFormatVersion() == 4 ||
		result.proposedCandidate.CompilerFormatVersion() == 4
	if imported {
		encoder.write([]byte(impactHashDomainV2))
	} else {
		encoder.write([]byte(impactHashDomainV1))
	}
	encoder.writeText(result.baseline.scope.WorkspaceID().String())
	encoder.writeText(result.baseline.scope.NetworkID().String())
	encoder.writeRevisionVector(result.baseline.revisionVector)
	encoder.writeRevisionVector(result.proposedVector)
	if result.baseline.hasActiveRelease {
		encoder.write([]byte{1})
		encoder.writeText(result.baseline.releaseID.String())
	} else {
		encoder.write([]byte{0})
		encoder.writeText("")
	}
	encoder.writeInt64(int64(result.baseline.candidate.CompilerFormatVersion()))
	currentHash := result.baseline.candidate.SemanticHash().Bytes()
	encoder.write(currentHash[:])
	encoder.writeInt64(int64(result.proposedCandidate.CompilerFormatVersion()))
	proposedHash := result.proposedCandidate.SemanticHash().Bytes()
	encoder.write(proposedHash[:])
	encoder.writeRelationships(result.addedRelationships)
	encoder.writeRelationships(result.removedRelationships)
	encoder.writeExplanations(result.addedExplanations)
	encoder.writeExplanations(result.removedExplanations)
	if imported {
		encoder.writeImportedIntents(result.addedImportedIntents)
		encoder.writeImportedIntents(result.removedImportedIntents)
	}
	encoder.writeUint64(uint64(len(result.affectedDevices)))
	for _, id := range result.affectedDevices {
		encoder.writeText(id.String())
	}
	encoder.writeUint64(uint64(len(result.affectedResources)))
	for _, id := range result.affectedResources {
		encoder.writeText(id.String())
	}
	encoder.writeUint64(uint64(len(result.affectedGroups)))
	for _, id := range result.affectedGroups {
		encoder.writeText(id.String())
	}
	encoder.writeUint64(uint64(len(result.unsupported)))
	for _, capability := range result.unsupported {
		encoder.write([]byte{byte(capability)})
	}
	var resultHash ImpactHash
	copy(resultHash[:], encoder.digest.Sum(nil))
	return resultHash
}

func (encoder impactEncoder) writeRevisionVector(vector accessgraph.RevisionVector) {
	for _, revision := range [...]int64{
		vector.NetworkRevision(),
		vector.InventoryRevision(),
		vector.GroupRevision(),
		vector.PolicyRevision(),
		vector.DNSRevision(),
		vector.RouteRevision(),
		vector.SharingRevision(),
		vector.IsolationGeneration(),
	} {
		encoder.writeInt64(revision)
	}
}

func (encoder impactEncoder) writeRelationships(values []Relationship) {
	encoder.writeUint64(uint64(len(values)))
	for _, value := range values {
		encoder.writeText(value.sourceNodeID.String())
		encoder.writeText(value.destinationNodeID.String())
		encoder.write([]byte{byte(value.protocol)})
		encoder.writeUint16(value.firstPort)
		encoder.writeUint16(value.lastPort)
	}
}

func (encoder impactEncoder) writeExplanations(values []Explanation) {
	encoder.writeUint64(uint64(len(values)))
	for _, value := range values {
		encoder.writeText(value.ruleID.String())
		encoder.writeText(value.sourceNodeID.String())
		encoder.writeText(value.destinationNodeID.String())
		encoder.write([]byte{byte(value.protocol)})
		encoder.writeUint64(uint64(len(value.destinationPortRanges)))
		for _, portRange := range value.destinationPortRanges {
			encoder.writeUint16(portRange.First())
			encoder.writeUint16(portRange.Last())
		}
		encoder.write([]byte{byte(value.selectorKind)})
		encoder.writeText(value.resourceID.String())
		encoder.writeInt64(value.resourceVersion)
		encoder.writeInt64(value.targetGeneration)
		encoder.writeInt64(value.inventoryRevision)
		resourceHash := value.resourceSemanticHash.Bytes()
		encoder.write(resourceHash[:])
		encoder.writeText(value.groupID.String())
		encoder.writeInt64(value.groupVersion)
		encoder.writeInt64(value.definitionVersion)
		encoder.writeInt64(value.groupRevision)
		groupHash := value.groupSemanticHash.Bytes()
		encoder.write(groupHash[:])
	}
}

func (encoder impactEncoder) writeText(value string) {
	encoder.writeUint64(uint64(len(value)))
	encoder.write([]byte(value))
}

func (encoder impactEncoder) writeUint16(value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	encoder.write(encoded[:])
}

func (encoder impactEncoder) writeUint64(value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	encoder.write(encoded[:])
}

func (encoder impactEncoder) writeInt64(value int64) {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutVarint(encoded[:], value)
	encoder.write(encoded[:length])
}

func (encoder impactEncoder) write(value []byte) {
	// hash.Hash.Write documents that it never returns an error.
	_, _ = encoder.digest.Write(value)
}
