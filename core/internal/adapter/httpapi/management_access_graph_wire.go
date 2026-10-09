package httpapi

import (
	"encoding/hex"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// explainedPolicyContext tells a person why the decision came out as it did.
// It names only participants of the caller's Network and, for a shared
// target, the contract facts the consumer already sees on its share.
type explainedPolicyContext struct {
	Source explainedPolicyParticipant  `json:"source"`
	Target explainedPolicyTargetDetail `json:"target"`
	Share  *explainedPolicyShare       `json:"share"`
}

type explainedPolicyParticipant struct {
	State string  `json:"state"`
	Name  *string `json:"name"`
}

type explainedPolicyTargetDetail struct {
	Kind  string  `json:"kind"`
	State string  `json:"state"`
	Name  *string `json:"name"`
}

type explainedPolicyShare struct {
	TrustContractID       string  `json:"trust_contract_id"`
	State                 string  `json:"state"`
	ExpiresAt             *string `json:"expires_at"`
	ProviderWorkspaceCode string  `json:"provider_workspace_code"`
	ProviderNetworkCode   string  `json:"provider_network_code"`
	AccessName            *string `json:"access_name"`
}

// newExplainedPolicy renders one validated explanation for the wire.
func newExplainedPolicy(query accessgraph.Query, result accessgraph.Result) explainedPolicy {
	snapshot := result.Snapshot()
	explained := explainedPolicy{
		Decision: result.Decision().String(), Reason: result.Reason().String(),
		Action:  newExplainedPolicyAction(query),
		Subject: explainedPolicySubject{DeviceID: query.SourceNodeID().String()},
		Target:  newExplainedPolicyTarget(query), Evidence: newExplainedPolicyEvidence(snapshot),
		Paths: newExplainedPolicyPaths(result.Paths()), Truncated: result.Truncated(),
		Context: newExplainedPolicyContext(snapshot),
	}
	if reason, denied := result.DenyReason(); denied {
		value := reason.String()
		explained.DenyReason = &value
	}
	return explained
}

func newExplainedPolicyAction(query accessgraph.Query) explainedPolicyAction {
	action := explainedPolicyAction{Name: "network.connect", Protocol: query.Protocol().String()}
	if query.Protocol() != policy.ProtocolICMP {
		port := int(query.DestinationPort())
		action.DestinationPort = &port
	}
	return action
}

func newExplainedPolicyTarget(query accessgraph.Query) explainedPolicyTarget {
	switch {
	case query.DestinationNodeID().IsValid():
		return explainedPolicyTarget{DeviceID: query.DestinationNodeID().String()}
	case query.DestinationResourceID().IsValid():
		return explainedPolicyTarget{ResourceID: query.DestinationResourceID().String()}
	default:
		return explainedPolicyTarget{ImportedResourceID: query.DestinationImportedResourceID().String()}
	}
}

func newExplainedPolicyEvidence(snapshot accessgraph.Snapshot) explainedPolicyEvidence {
	releaseID, compilerFormat, semanticHash, hasActiveRelease := snapshot.ActiveRelease()
	return newExplainedPolicyEvidenceFrom(
		snapshot.RevisionVector(), releaseID.String(), compilerFormat, semanticHash, hasActiveRelease,
	)
}

// newExplainedPolicyEvidenceFrom renders the authority vector and active
// release shared by explanations and graph listings.
func newExplainedPolicyEvidenceFrom(
	revision accessgraph.RevisionVector,
	releaseID string,
	compilerFormat int,
	semanticHash publication.SemanticHash,
	hasActiveRelease bool,
) explainedPolicyEvidence {
	evidence := explainedPolicyEvidence{
		NetworkRevision: revision.NetworkRevision(), InventoryRevision: revision.InventoryRevision(),
		GroupRevision: revision.GroupRevision(), PolicyRevision: revision.PolicyRevision(),
		DNSRevision: revision.DNSRevision(), RouteRevision: revision.RouteRevision(),
		SharingRevision: revision.SharingRevision(), IsolationGeneration: revision.IsolationGeneration(),
		HasActiveRelease: hasActiveRelease,
	}
	if hasActiveRelease {
		hash := semanticHash.Bytes()
		evidence.ReleaseID = releaseID
		evidence.CompilerFormatVersion = compilerFormat
		evidence.SemanticHash = hex.EncodeToString(hash[:])
	}
	return evidence
}

func newExplainedPolicyPaths(paths []accessgraph.Path) []explainedPolicyPath {
	rendered := make([]explainedPolicyPath, len(paths))
	for index, path := range paths {
		ranges := path.DestinationPortRanges()
		ports := make([]publishPolicyPortRangeRequest, len(ranges))
		for rangeIndex, portRange := range ranges {
			ports[rangeIndex] = publishPolicyPortRangeRequest{First: int(portRange.First()), Last: int(portRange.Last())}
		}
		rendered[index] = explainedPolicyPath{
			ProjectionID: path.ProjectionID().String(), AccessRuleID: path.RuleID().String(),
			SourceDeviceID: path.SourceNodeID().String(), Protocol: path.Protocol().String(),
			DestinationPortRanges: ports, SelectorKind: path.SelectorKind().String(),
		}
		if path.DestinationNodeID().IsValid() {
			rendered[index].DestinationDeviceID = path.DestinationNodeID().String()
		}
		if path.DestinationResourceID().IsValid() {
			rendered[index].DestinationResourceID = path.DestinationResourceID().String()
		}
		if path.DestinationGroupID().IsValid() {
			rendered[index].DestinationGroupID = path.DestinationGroupID().String()
		}
		if path.DestinationImportedResourceID().IsValid() {
			rendered[index].DestinationImportedResourceID = path.DestinationImportedResourceID().String()
			rendered[index].TrustContractID = path.TrustContractID().String()
		}
		if path.SourceDeviceGroupID().IsValid() {
			rendered[index].SourceDeviceGroupID = path.SourceDeviceGroupID().String()
		}
		if path.DestinationDeviceGroupID().IsValid() {
			rendered[index].DestinationDeviceGroupID = path.DestinationDeviceGroupID().String()
		}
		if path.SourceIdentityGroupID().IsValid() {
			rendered[index].SourceIdentityGroupID = path.SourceIdentityGroupID().String()
		}
		if path.SourceTagID().IsValid() {
			rendered[index].SourceDeviceTagID = path.SourceTagID().String()
		}
		if path.DestinationTagID().IsValid() {
			rendered[index].DestinationDeviceTagID = path.DestinationTagID().String()
		}
	}
	return rendered
}

func newExplainedPolicyContext(snapshot accessgraph.Snapshot) explainedPolicyContext {
	source, target := snapshot.Source(), snapshot.Target()
	context := explainedPolicyContext{
		Source: explainedPolicyParticipant{State: source.State().String(), Name: optionalText(source.Name())},
		Target: explainedPolicyTargetDetail{
			Kind: snapshot.TargetKind().String(), State: target.State().String(), Name: optionalText(target.Name()),
		},
	}
	if share, ok := snapshot.Share(); ok {
		context.Share = newExplainedPolicyShare(share)
	}
	return context
}

func optionalText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
