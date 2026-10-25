package mtcp

import (
	"context"
	"errors"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// ClusterJoins opens Kubernetes gateway replicas' requests and completes
// the approved ones into gateway Devices (kubecluster.JoinStore and
// kubecluster.JoinCompletionStore).
type ClusterJoins interface {
	OpenReplicaRequest(ctx context.Context, attempt kubecluster.JoinAttempt) (kubecluster.JoinTicket, error)
	CompleteReplicaRequest(ctx context.Context, scope network.Scope, requestID kubecluster.RequestID,
		identity node.RegistrationIdentity) (kubecluster.Completion, error)
}

// ClusterJoinSecrets proposes a request's ID and the nonce its code binds:
// Core chooses both, never the replica.
type ClusterJoinSecrets interface {
	NewRequestID() (kubecluster.RequestID, error)
	NewRequestNonce() ([32]byte, error)
}

// clusterJoinWait is the request a pending cluster join waits for.
type clusterJoinWait struct {
	scope     network.Scope
	requestID kubecluster.RequestID
	identity  node.RegistrationIdentity
}

var (
	clusterJoinsDisabled = rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
		message: "this deployment does not accept Kubernetes cluster joins"}
	joinKeyInvalid = rejection{code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID,
		message: "the join key is not valid"}
	joinRequestEnded = rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
		message: "the join request was rejected or cancelled; ask an administrator"}
	joinRequestExpired = rejection{code: mtcpv1.RegisterResponse_Rejected_EXPIRED,
		message: "the approved join request was not completed in time; join again"}
)

// registerWithClusterJoin opens, or finds again, the replica's request and
// waits on this session for an administrator to approve it (mtcp-v1 §6.6).
func (conversation *conversation) registerWithClusterJoin(ctx context.Context, machine control.AuthenticatedMachine,
	keys provenKeys, hostname node.Hostname, join *mtcpv1.RegisterRequest_ClusterJoin) error {
	options := conversation.application.options
	if options.ClusterJoins == nil {
		return conversation.reject(clusterJoinsDisabled)
	}
	presentation, err := enrollment.ParseJoinKeyPresentation(join.GetJoinKey())
	if err != nil {
		return conversation.reject(joinKeyInvalid)
	}
	raw := join.GetReported()
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	reported, err := kubecluster.CanonicalReported(raw)
	if err != nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "reported must be a JSON object of at most 16 short strings"})
	}
	// Opening a request reads and writes the database: one per sign-in
	// and per reconnect, like a browser approval.
	if wait, ok := conversation.browser.spend(conversation.application.now(), 1); !ok {
		options.Metrics.limited(limitBrowser)
		return conversation.sendError(mtcpv1.Error_OVERLOADED, "too many join requests", retryAfterMS(wait))
	}
	// The request binds the session's machine key, which the handshake
	// proved, and the node key proven in this request.
	machineKey := node.MachineKey(conversation.session.Machine())
	identity, err := node.NewRegistrationIdentity(machineKey, keys.node)
	if err != nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "invalid registration"})
	}
	requestID, idErr := options.ClusterJoinSecrets.NewRequestID()
	nonce, nonceErr := options.ClusterJoinSecrets.NewRequestNonce()
	if idErr != nil || nonceErr != nil {
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
	ticket, err := options.ClusterJoins.OpenReplicaRequest(ctx, kubecluster.JoinAttempt{
		Presentation: presentation, MachineKey: machineKey, NodeKey: keys.node, Hostname: hostname,
		Reported: reported, RequestID: requestID, Nonce: nonce,
	})
	if err != nil {
		return conversation.joinRefused(ctx, err)
	}
	wait := clusterJoinWait{scope: ticket.Scope, requestID: ticket.Request.ID(), identity: identity}
	// A request approved or completed before this session asked again
	// completes now; one still waiting completes when approved.
	if ticket.Request.Lifecycle().State() != kubecluster.RequestPending {
		if done := conversation.checkClusterJoin(ctx, keys, wait); done {
			return nil
		}
	}
	// A waiting request lives as long as its key; an approved one until
	// its completion deadline; a completed one only needs another check.
	expires := conversation.application.now().Add(maxApprovalTTL)
	end := ticket.Request.Lifecycle().ExpiresAt()
	if _, _, deadline, approved := ticket.Request.Approval(); approved &&
		ticket.Request.Lifecycle().State() == kubecluster.RequestApproved {
		end = deadline
	}
	if end.Before(expires) {
		expires = end
	}
	if err := conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
		Outcome: &mtcpv1.RegisterResponse_Pending_{Pending: &mtcpv1.RegisterResponse_Pending{
			ExpiresMs: expires.UnixMilli(),
			AdminApproval: &mtcpv1.RegisterResponse_AdminApproval{
				ClusterId: ticket.ClusterID.String(), RequestId: ticket.Request.ID().String(),
				RequestNonce: ticket.Nonce[:],
			},
		}},
	}); err != nil {
		return err
	}
	conversation.wait(approval{machine: machine, keys: keys, hostname: hostname, expires: expires, join: &wait})
	return nil
}

// joinRefused answers a request the store did not open without telling a
// wrong secret from an unknown key.
func (conversation *conversation) joinRefused(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, kubecluster.ErrJoinRefused):
		return conversation.reject(joinKeyInvalid)
	case errors.Is(err, kubecluster.ErrKeyNotUsable):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_EXHAUSTED,
			message: "the join key is revoked, expired or used up"})
	case errors.Is(err, kubecluster.ErrKeysInUse):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_CONFLICT,
			message: "the keys belong to a Device or another registration"})
	case errors.Is(err, kubecluster.ErrQueueFull):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
			message: "too many replicas wait for approval with this join key"})
	case errors.Is(err, kubecluster.ErrInvalid):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "invalid registration"})
	default:
		if ctx.Err() == nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp cluster join failed",
				"error_code", "cluster_join_unavailable")
		}
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
}

// checkClusterJoin completes an approved request and authorizes it on the
// session, or answers a request that ended. It reports whether the wait is
// over; transient failures are checked again on the next tick.
func (conversation *conversation) checkClusterJoin(ctx context.Context, keys provenKeys,
	wait clusterJoinWait) bool {
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	completion, err := conversation.application.options.ClusterJoins.CompleteReplicaRequest(ctx, wait.scope,
		wait.requestID, wait.identity)
	switch {
	case errors.Is(err, kubecluster.ErrExpired):
		_ = conversation.reject(joinRequestExpired)
		return true
	case errors.Is(err, kubecluster.ErrNotWaiting), errors.Is(err, kubecluster.ErrKeyNotUsable),
		errors.Is(err, kubecluster.ErrNotFound):
		_ = conversation.reject(joinRequestEnded)
		return true
	case errors.Is(err, ipam.ErrAddressExhausted):
		_ = conversation.reject(networkFull)
		return true
	case err != nil:
		if ctx.Err() == nil && !errors.Is(err, kubecluster.ErrConflict) {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp cluster join completion failed",
				"error_code", "cluster_join_unavailable")
		}
		return false
	case completion.State != kubecluster.RequestCompleted:
		return false
	}
	conversation.authorize(keys.node, keys.disco, completion.Result.Hostname(), true)
	return true
}
