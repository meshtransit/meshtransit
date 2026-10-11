package mtcp

import (
	"context"
	"errors"
	"strings"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/keyrotation"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// Registrations commits enrollment-key registrations and node key rotations
// bound to the session's machine key (control.RegistrationService).
type Registrations interface {
	Register(ctx context.Context, machine control.AuthenticatedMachine,
		request control.RegistrationRequest) (registration.Result, error)
}

// RegistrationIDs proposes server-owned registration identities.
type RegistrationIDs interface {
	NewRegistrationID() (enrollment.RegistrationID, error)
}

// BrowserIssuer issues, or re-issues for a follow-up, an approval URL bound
// to a machine key, node key and hostname (control.BrowserRegistrationService).
type BrowserIssuer interface {
	RegisterBrowser(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		hostname node.Hostname, followupURL string) (string, error)
}

// BrowserApproval commits a browser-approved registration, or reports that
// the approval has not happened (control.BrowserCompletionService).
type BrowserApproval interface {
	CompleteBrowser(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		hostname node.Hostname, followupURL string) (registration.Result, bool, error)
}

// DeviceLogout deauthorizes the Device whose current keys the node holds
// (control.DeviceLogoutService).
type DeviceLogout interface {
	Logout(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key) (control.DeviceLogout, error)
}

// errLoggedOut ends a session after a Logout (mtcp-v1 §6.5).
var errLoggedOut = errors.New("mtcp: device logged out")

const (
	registrationTimeout  = 15 * time.Second
	approvalPollInterval = 2 * time.Second
	maxApprovalTTL       = 10 * time.Minute // mtcp-v1 §6.2
	approvalPath         = "/register/v1/"
	maxResumeHandle      = 256
)

// approval is a pending browser approval the session waits for. A zero
// approval cancels the wait.
type approval struct {
	machine  control.AuthenticatedMachine
	keys     provenKeys
	hostname node.Hostname
	url      string
	expires  time.Time
}

// rejection is a RegisterResponse{rejected} outcome.
type rejection struct {
	code    mtcpv1.RegisterResponse_Rejected_Code
	message string
}

// register answers a RegisterRequest (mtcp-v1 §6.1, §6.2). Outcomes are
// RegisterResponse messages; only dependency failures send an Error.
func (conversation *conversation) register(ctx context.Context, request *mtcpv1.RegisterRequest) error {
	options := conversation.application.options
	if options.Registrations == nil && options.BrowserIssuer == nil {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "registration is not available", 0)
	}
	conversation.wait(approval{}) // a new request replaces any pending approval
	keys, hostname, rejected := conversation.validateRegistration(request)
	if rejected != nil {
		return conversation.reject(*rejected)
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	switch method := request.GetAuth().GetMethod().(type) {
	case *mtcpv1.RegisterRequest_Auth_EnrollmentKey:
		return conversation.registerWithCredential(ctx, machine, keys, hostname, method.EnrollmentKey)
	case *mtcpv1.RegisterRequest_Auth_Interactive:
		return conversation.registerInteractively(ctx, machine, keys, hostname,
			method.Interactive.GetResumeHandle())
	case *mtcpv1.RegisterRequest_Auth_Resume:
		// Renewal without a person would let a machine key keep a Device
		// alive indefinitely; until a Network policy allows it, renewal
		// goes through an approval.
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_EXPIRED,
			message: "renewal needs an interactive approval"})
	default:
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "no authentication method"})
	}
}

// validateRegistration checks the keys, their proofs of possession and the
// hostname (mtcp-v1 §6.1, §6.4).
func (conversation *conversation) validateRegistration(request *mtcpv1.RegisterRequest) (provenKeys, node.Hostname,
	*rejection) {
	invalid := func(message string) (provenKeys, node.Hostname, *rejection) {
		return provenKeys{}, node.Hostname{}, &rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID, message: message}
	}
	keys, ok := conversation.provenKeys(request.GetNodeKey(), request.GetNodeKeyProof(), request.GetDiscoKey(),
		request.GetDiscoKeyProof())
	if !ok {
		return invalid("keys or proofs of possession are invalid")
	}
	hostname, err := node.ParseHostname(request.GetHostinfo().GetHostname())
	if err != nil {
		return invalid("invalid hostname")
	}
	return keys, hostname, nil
}

// provenKeys validates a node key and disco key with their proofs.
func (conversation *conversation) provenKeys(nodeKey, nodeProof, discoKey, discoProof []byte) (provenKeys, bool) {
	if len(nodeKey) != key.Size || len(discoKey) != key.Size || string(nodeKey) == string(discoKey) ||
		!conversation.session.VerifyKeyProof(nodeKey, nodeProof) ||
		!conversation.session.VerifyKeyProof(discoKey, discoProof) {
		return provenKeys{}, false
	}
	parsed := node.Key(nodeKey)
	disco, err := node.NewDiscoveryKey([key.Size]byte(discoKey))
	if !parsed.IsValid() || err != nil {
		return provenKeys{}, false
	}
	return provenKeys{node: parsed, disco: disco}, true
}

// provenKeys are a node key and disco key whose possession the node proved
// in this session.
type provenKeys struct {
	node  node.Key
	disco node.DiscoveryKey
}

func (conversation *conversation) registerWithCredential(ctx context.Context, machine control.AuthenticatedMachine,
	keys provenKeys, hostname node.Hostname, presented string) error {
	options := conversation.application.options
	if options.Registrations == nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
			message: "enrollment keys are not accepted here"})
	}
	credential, err := enrollment.ParseCredentialPresentation(presented)
	if err != nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID,
			message: "the enrollment key is not valid"})
	}
	registrationID, err := options.RegistrationIDs.NewRegistrationID()
	if err != nil {
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
	request, err := control.NewRegistrationRequest(control.RegistrationRequestParams{
		RegistrationID: registrationID, Credential: credential, NodeKey: keys.node, Hostname: hostname,
	})
	if err != nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "invalid registration"})
	}
	result, err := options.Registrations.Register(ctx, machine, request)
	if err != nil {
		return conversation.registrationFailed(ctx, err)
	}
	conversation.authorize(keys.node, keys.disco, result.Hostname(), true)
	return nil
}

// registrationFailed answers a failed registration without revealing which
// check failed or anything about other tenants.
func (conversation *conversation) registrationFailed(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, intake.ErrAuthenticationFailed):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID,
			message: "the enrollment key is not valid"})
	case errors.Is(err, control.ErrInvalidRegistrationRequest):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
			message: "invalid registration"})
	case errors.Is(err, registration.ErrIntentConflict), errors.Is(err, keyrotation.ErrConflict):
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_CONFLICT,
			message: "the keys conflict with an existing Device"})
	case errors.Is(err, ipam.ErrAddressExhausted):
		// Permanent until an admin adds an address range; retrying would
		// only load Core.
		return conversation.reject(networkFull)
	default:
		if ctx.Err() == nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp registration failed",
				"error_code", "registration_unavailable")
		}
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
}

// registerInteractively answers with an approval URL, or completes an
// approval the node resumes after a reconnect (mtcp-v1 §6.2).
func (conversation *conversation) registerInteractively(ctx context.Context, machine control.AuthenticatedMachine,
	keys provenKeys, hostname node.Hostname, handle string) error {
	nodeKey := keys.node
	options := conversation.application.options
	if options.BrowserIssuer == nil {
		return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
			message: "interactive registration is not enabled"})
	}
	prefix := options.ApprovalOrigin + approvalPath
	var followup string
	if handle != "" {
		if len(handle) > maxResumeHandle || strings.ContainsAny(handle, "/?#") {
			return conversation.reject(rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
				message: "invalid resume handle"})
		}
		followup = prefix + handle
		result, found, err := options.BrowserApproval.CompleteBrowser(ctx, machine, nodeKey, hostname, followup)
		switch {
		case errors.Is(err, control.ErrInvalidBrowserRegistration):
			return conversation.reject(expiredApproval)
		case errors.Is(err, ipam.ErrAddressExhausted):
			return conversation.reject(networkFull)
		case err != nil:
			return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
		case found:
			conversation.authorize(nodeKey, keys.disco, result.Hostname(), true)
			return nil
		}
	}
	approvalURL, err := options.BrowserIssuer.RegisterBrowser(ctx, machine, nodeKey, hostname, followup)
	switch {
	case errors.Is(err, control.ErrInvalidBrowserRegistration):
		// Unknown, expired, or bound to other keys: a handle never moves.
		return conversation.reject(expiredApproval)
	case err != nil:
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
	token, ok := strings.CutPrefix(approvalURL, prefix)
	if !ok || token == "" {
		return conversation.sendError(mtcpv1.Error_INTERNAL, "registration unavailable", 2000)
	}
	expires := conversation.application.now().Add(options.ApprovalTTL)
	// The resume handle is the URL token: completing an approval also needs
	// this session's machine key and node key, so the URL alone authorizes
	// nothing (mtcp-v1 §6.2).
	if err := conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
		Outcome: &mtcpv1.RegisterResponse_Pending_{Pending: &mtcpv1.RegisterResponse_Pending{
			ApprovalUrl: approvalURL, ResumeHandle: token, ExpiresMs: expires.UnixMilli(),
		}},
	}); err != nil {
		return err
	}
	conversation.wait(approval{machine: machine, keys: keys, hostname: hostname, url: approvalURL,
		expires: expires})
	return nil
}

var networkFull = rejection{code: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED,
	message: "the Network has no free address; its administrator can add an address range"}

var expiredApproval = rejection{code: mtcpv1.RegisterResponse_Rejected_EXPIRED,
	message: "the approval is unknown or has expired; start a new one"}

// wait replaces the pending approval the session watches.
func (conversation *conversation) wait(next approval) {
	select {
	case <-conversation.approvals:
	default:
	}
	conversation.approvals <- next // capacity 1, drained above; Receive is serial
	conversation.startApprovals()
}

// watchApprovalsWithin bounds the approval watcher by Run's context and
// starts it if an approval arrived before Run did.
func (conversation *conversation) watchApprovalsWithin(ctx context.Context) {
	conversation.approvalMu.Lock()
	defer conversation.approvalMu.Unlock()
	conversation.approvalParent = ctx
	if conversation.approvalPending {
		conversation.startApprovalsLocked()
	}
}

// startApprovals starts the approval watcher once, for Run's life.
func (conversation *conversation) startApprovals() {
	conversation.approvalMu.Lock()
	defer conversation.approvalMu.Unlock()
	if conversation.approvalParent == nil {
		conversation.approvalPending = true // Run starts it
		return
	}
	conversation.startApprovalsLocked()
}

func (conversation *conversation) startApprovalsLocked() {
	if conversation.approvalDone != nil || conversation.approvalStopped {
		return
	}
	ctx, cancel := context.WithCancel(conversation.approvalParent)
	done := make(chan struct{})
	conversation.approvalCancel, conversation.approvalDone = cancel, done
	go func() {
		defer close(done)
		conversation.awaitApprovals(ctx)
	}()
}

// stopApprovals ends and joins the approval watcher, if it ever started.
func (conversation *conversation) stopApprovals() {
	conversation.approvalMu.Lock()
	conversation.approvalStopped = true
	cancel, done := conversation.approvalCancel, conversation.approvalDone
	conversation.approvalMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// awaitApprovals checks the pending approval until it is approved or
// expires, so the node never polls (mtcp-v1 §6.2).
func (conversation *conversation) awaitApprovals(ctx context.Context) {
	ticker := time.NewTicker(conversation.application.poll)
	defer ticker.Stop()
	var current approval
	for {
		select {
		case <-ctx.Done():
			return
		case current = <-conversation.approvals:
		case <-ticker.C:
			if !current.keys.node.IsValid() {
				continue
			}
			if !conversation.application.now().Before(current.expires) {
				_ = conversation.reject(expiredApproval)
				current = approval{}
				continue
			}
			if conversation.checkApproval(ctx, current) {
				current = approval{}
			}
		}
	}
}

func (conversation *conversation) checkApproval(ctx context.Context, pending approval) bool {
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	result, found, err := conversation.application.options.BrowserApproval.CompleteBrowser(ctx, pending.machine,
		pending.keys.node, pending.hostname, pending.url)
	if err != nil {
		if errors.Is(err, control.ErrInvalidBrowserRegistration) {
			_ = conversation.reject(expiredApproval)
			return true
		}
		return false // transient; checked again on the next tick
	}
	if !found {
		return false
	}
	conversation.authorize(pending.keys.node, pending.keys.disco, result.Hostname(), true)
	return true
}

// rotate answers RotateNodeKey (mtcp-v1 §6.3).
func (conversation *conversation) rotate(ctx context.Context, request *mtcpv1.RotateNodeKey) error {
	options := conversation.application.options
	if options.Registrations == nil {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "rotation is not available", 0)
	}
	keys, ok := conversation.provenKeys(request.GetNewNodeKey(), request.GetNodeKeyProof(),
		request.GetNewDiscoKey(), request.GetDiscoKeyProof())
	newKey := keys.node
	if !ok {
		return conversation.sendError(mtcpv1.Error_INVALID, "keys or proofs of possession are invalid", 0)
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	// A repeat after a crash: the new key already is the Device's key.
	if snapshot, current := conversation.ownsKey(ctx, machine, newKey); current {
		return conversation.rotated(keys, snapshot.Hostname(), snapshot.KeyExpiry())
	}
	oldKey, hostname, expiry := conversation.rotationBase()
	if oldKey.IsValid() && !hostname.IsValid() {
		// No map on this session yet: the current key's snapshot names the
		// Device, and proves the key still is current.
		if snapshot, current := conversation.ownsKey(ctx, machine, oldKey); current {
			hostname, expiry = snapshot.Hostname(), snapshot.KeyExpiry()
		}
	}
	if !oldKey.IsValid() || !hostname.IsValid() {
		return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "rotation needs an authorized Device", 0)
	}
	registrationID, err := options.RegistrationIDs.NewRegistrationID()
	if err != nil {
		return conversation.sendError(mtcpv1.Error_INTERNAL, "rotation unavailable", 2000)
	}
	command, err := control.NewRegistrationRequest(control.RegistrationRequestParams{
		RegistrationID: registrationID, NodeKey: newKey, OldNodeKey: oldKey, Hostname: hostname,
	})
	if err != nil {
		return conversation.sendError(mtcpv1.Error_INVALID, "invalid rotation", 0)
	}
	if _, err := options.Registrations.Register(ctx, machine, command); err != nil {
		switch {
		case errors.Is(err, keyrotation.ErrConflict), errors.Is(err, registration.ErrIntentConflict):
			return conversation.sendError(mtcpv1.Error_NOT_PERMITTED, "the keys conflict with an existing Device", 0)
		case errors.Is(err, keyrotation.ErrNotFound):
			return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "rotation needs an authorized Device", 0)
		default:
			return conversation.sendError(mtcpv1.Error_INTERNAL, "rotation unavailable", 2000)
		}
	}
	return conversation.rotated(keys, hostname, expiry)
}

// ownsKey reports whether nodeKey is the current key of this machine's
// Device.
func (conversation *conversation) ownsKey(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key) (mapsession.Snapshot, bool) {
	request, err := mapsession.NewRequest(nodeKey)
	if err == nil && conversation.session.Supports("device-alias.v1") {
		// Open records the client's alias support; report the same as the stream.
		request, err = request.WithDeviceAliasVersion(1)
	}
	if err != nil {
		return mapsession.Snapshot{}, false
	}
	snapshot, err := conversation.application.options.Snapshots.Open(ctx, machine, request)
	return snapshot, err == nil
}

// rotationBase returns the key a rotation replaces: the authorized key of
// the session, or after a crash the ClientHello's key.
func (conversation *conversation) rotationBase() (node.Key, node.Hostname, time.Time) {
	conversation.mu.Lock()
	oldKey, hostname := conversation.nodeKey, conversation.hostname
	conversation.mu.Unlock()
	var expiry time.Time
	if snapshot, ok := conversation.sink.snapshot(); ok {
		if !oldKey.IsValid() {
			oldKey = snapshot.NodeKey()
		}
		if !hostname.IsValid() {
			hostname = snapshot.Hostname()
		}
		expiry = snapshot.KeyExpiry()
	}
	if hello := conversation.session.Hello().GetNodeKey(); !oldKey.IsValid() && len(hello) == key.Size {
		oldKey = node.Key(hello)
	}
	return oldKey, hostname, expiry
}

func (conversation *conversation) rotated(keys provenKeys, hostname node.Hostname, expiry time.Time) error {
	response := &mtcpv1.RotateNodeKeyResponse{NodeKey: keys.node[:]}
	if !expiry.IsZero() {
		response.KeyExpiryMs = expiry.UnixMilli()
	}
	if err := conversation.session.Send(sharedmtcp.MessageRotateNodeKeyResponse, response); err != nil {
		return err
	}
	// The stream restarts with the new key; peers receive it as one map
	// change from the committed rotation.
	conversation.authorize(keys.node, keys.disco, hostname, false)
	return nil
}

func (conversation *conversation) reject(rejected rejection) error {
	return conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
		Outcome: &mtcpv1.RegisterResponse_Rejected_{Rejected: &mtcpv1.RegisterResponse_Rejected{
			Code: rejected.code, Message: rejected.message,
		}},
	})
}

// sendError sends a non-fatal Error; the session continues.
func (conversation *conversation) sendError(code mtcpv1.Error_Code, message string, retryAfterMS uint32) error {
	return conversation.session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: code, Message: message,
		RetryAfterMs: retryAfterMS})
}

// logout answers Logout: the Device is revoked, the node is told LOGGED_OUT
// and the session ends (mtcp-v1 §6.5).
func (conversation *conversation) logout(ctx context.Context) error {
	logout := conversation.application.options.Logout
	if logout == nil {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "logout is not available", 0)
	}
	nodeKey, disco, hostname := conversation.suspendStream()
	if !nodeKey.IsValid() {
		return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "logout needs an authorized Device", 0)
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	if _, err := logout.Logout(ctx, machine, nodeKey); err != nil {
		conversation.authorize(nodeKey, disco, hostname, false) // nothing changed: the stream resumes
		if errors.Is(err, control.ErrDeviceLogoutNotFound) {
			return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "logout needs an authorized Device", 0)
		}
		return conversation.sendError(mtcpv1.Error_INTERNAL, "logout unavailable", 2000)
	}
	if err := conversation.session.Send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{
		State: mtcpv1.Lifecycle_LOGGED_OUT, Reason: "the Device logged out",
	}); err != nil {
		return err
	}
	return errLoggedOut
}

// suspendStream ends the running stream without a Lifecycle, so the
// revocation a logout commits does not reach the node as EXPIRED first.
func (conversation *conversation) suspendStream() (node.Key, node.DiscoveryKey, node.Hostname) {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	nodeKey, disco, hostname := conversation.nodeKey, conversation.disco, conversation.hostname
	if !hostname.IsValid() {
		if snapshot, ok := conversation.sink.snapshot(); ok {
			hostname = snapshot.Hostname()
		}
	}
	conversation.nodeKey = node.Key{}
	conversation.generation++
	if conversation.restart != nil {
		conversation.restart()
	}
	return nodeKey, disco, hostname
}
