package mtcp

import (
	"context"
	"errors"
	"strings"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/adapter/kubetoken"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubejoin"
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
	trust, refused := podJoinTrust(join, conversation.application.now())
	if refused != nil {
		options.Metrics.limited(limitClusterJoinToken)
		return conversation.reject(*refused)
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
		Reported: reported, RequestID: requestID, Nonce: nonce, Trust: trust,
	})
	if err != nil {
		return conversation.joinRefused(ctx, err)
	}
	// The keys hold a request with other signing material: the replica's
	// code cannot match it. The request goes back so the replica prints its
	// own code, which the administrator sees differ (design §6.3).
	if ticket.TrustConflict {
		return conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
			Outcome: &mtcpv1.RegisterResponse_Rejected_{Rejected: &mtcpv1.RegisterResponse_Rejected{
				Code:    mtcpv1.RegisterResponse_Rejected_CONFLICT,
				Message: "the keys hold a join request with other signing material; reject it and join again",
				AdminApproval: &mtcpv1.RegisterResponse_AdminApproval{
					ClusterId: ticket.ClusterID.String(), RequestId: ticket.Request.ID().String(),
					RequestNonce: ticket.Nonce[:],
				},
			}},
		})
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
	// Schema 232: a request without trust, or a pod a live Device holds,
	// never completes.
	case errors.Is(err, kubecluster.ErrNotWaiting), errors.Is(err, kubecluster.ErrKeyNotUsable),
		errors.Is(err, kubecluster.ErrNotFound), errors.Is(err, kubecluster.ErrJoinAgain),
		errors.Is(err, kubecluster.ErrPodHeld):
		_ = conversation.reject(joinRequestEnded)
		return true
	case errors.Is(err, ipam.ErrAddressExhausted):
		_ = conversation.reject(networkFull)
		return true
	case errors.Is(err, kubecluster.ErrEdgeBudget):
		// A rule to the cluster would give a Device too many edges with this
		// replica; asked again on the next tick until the deadline.
		if ctx.Err() == nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp cluster join completion refused",
				"error_code", "cluster_join_edge_budget")
		}
		return false
	case err != nil:
		if ctx.Err() == nil && !errors.Is(err, kubecluster.ErrConflict) {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp cluster join completion failed",
				"error_code", "cluster_join_unavailable")
		}
		return false
	case completion.State != kubecluster.RequestCompleted:
		return false
	}
	conversation.prove(keys.node, true)
	if !conversation.session.ratchetJoinedGateway(ctx, keys.node) {
		return true
	}
	conversation.authorize(keys.node, keys.disco, completion.Result.Hostname(), true)
	return true
}

// podJoinTrust verifies the pod's ServiceAccount token against the issuer
// and keys the pod sent with it, and returns the trust the join code v2
// binds (K1.1 design §6.2). The administrator's code anchors the keys: a
// token signed by keys the pod made up only names a request no one approves.
func podJoinTrust(join *mtcpv1.RegisterRequest_ClusterJoin, now time.Time) (kubecluster.JoinTrust, *rejection) {
	invalid := func(message string) (kubecluster.JoinTrust, *rejection) {
		return kubecluster.JoinTrust{}, &rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID, message: message}
	}
	if join.GetServiceAccountToken() == "" {
		return invalid("a Kubernetes gateway joins with its pod's ServiceAccount token: upgrade meshgw and " +
			"mount a projected token with audience " + kubetoken.Audience)
	}
	jwks, err := kubejoin.ParseJWKS(join.GetServiceAccountJwks())
	if err != nil {
		// The error names the rule broken, never the input.
		return invalid("the cluster's signing keys are not accepted (" + err.Error() + ")")
	}
	issuer := join.GetServiceAccountIssuer()
	if !kubejoin.ValidIssuer(issuer) {
		return invalid("the cluster's issuer must be an https URL")
	}
	// Until administrators can replace a cluster's keys (K1.1b), a cluster
	// whose provider rotates them on its own would stop rotating gateway
	// keys: only cluster-local issuers join (design §14).
	if !clusterLocalIssuer(issuer) {
		return kubecluster.JoinTrust{}, &rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
			message: "only clusters with a cluster-local issuer (kind, kubeadm) join for now; " +
				"clusters with a public issuer (EKS, GKE, AKS) join once administrators can replace a cluster's keys"}
	}
	claims, err := kubetoken.Verify(join.GetServiceAccountToken(),
		kubetoken.Expectation{Issuer: issuer, JWKS: jwks}, now)
	if refused, ok := errors.AsType[*kubetoken.RefusedError](err); ok {
		message := "the pod's ServiceAccount token is refused (" + string(refused.Reason) + ")"
		switch refused.Reason {
		case kubetoken.ReasonMalformed:
			message += ": it must be a pod-bound token of Kubernetes 1.30 or newer, living at most 15 minutes"
		case kubetoken.ReasonAudience:
			message += ": its audience must be " + kubetoken.Audience
		}
		return invalid(message)
	}
	if err != nil {
		return invalid("the pod's ServiceAccount token is refused")
	}
	trust, err := kubecluster.NewJoinTrust(kubejoin.Trust{Issuer: issuer, JWKS: jwks, Namespace: claims.Namespace,
		ServiceAccount: claims.ServiceAccount, PodName: claims.PodName}, claims.KeyThumbprint)
	if err != nil {
		return invalid("the pod is not a StatefulSet replica")
	}
	return trust, nil
}

// clusterLocalIssuer reports whether issuer names a host only the cluster
// resolves, as kind and kubeadm clusters do.
func clusterLocalIssuer(issuer string) bool {
	authority, _, _ := strings.Cut(strings.TrimPrefix(issuer, "https://"), "/")
	host, _, _ := strings.Cut(strings.ToLower(authority), ":")
	return host == "kubernetes.default.svc" || strings.HasSuffix(host, ".svc") ||
		strings.HasSuffix(host, ".cluster.local")
}
