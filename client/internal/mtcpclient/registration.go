package mtcpclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	approvalPath = "/register/v1/"
	// followupWait is how long a follow-up waits on its session for the
	// approval before reporting it still pending (mtcp-v1 §6.2).
	followupWait  = 25 * time.Second
	answerTimeout = 30 * time.Second
)

// Register binds the profile's machine key to a Device with an enrollment
// key, or asks for or resumes a browser approval (mtcp-v1 §6).
func (c *Client) Register(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	keys, err := c.openKeys(material)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	if options.ClusterJoin != nil && c.gateway == nil {
		// A gateway's Device needs a client that proves its node key.
		return controlplane.RegistrationResult{}, fmt.Errorf("%w: a cluster join needs a gateway client",
			controlplane.ErrRegistration)
	}
	auth, err := registrationAuth(origin, options)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	if err := c.checkPinned(ctx, origin, keys.control, options.PinnedFingerprint); err != nil {
		return controlplane.RegistrationResult{}, err
	}
	s, keys, signInUsed, err := c.openRegistration(ctx, origin, keys, options)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	defer s.close()
	request, err := registerRequest(s, keys, options, auth)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	sent := attachSiblings(s, request, keys, options)
	if err := s.send(sharedmtcp.MessageRegisterRequest, request); err != nil {
		return controlplane.RegistrationResult{}, temporary(err)
	}
	wait := time.Duration(0)
	if options.FollowupURL != "" {
		wait = followupWait
	}
	if options.ClusterJoin != nil {
		// Core answers on this session once an administrator approves.
		wait = min(max(options.JoinWait, 0), maxJoinWait)
	}
	result, err := awaitRegistration(ctx, s, wait, options.ClusterJoin != nil, c.sessionError, c.coreNow)
	if err == nil && result.State == controlplane.RegistrationStateAlreadyInNetwork &&
		!slices.Contains(sent, result.SiblingMachineKey) {
		// Core names only a key this session proved (mtcp-v1 §6.2).
		return controlplane.RegistrationResult{}, fmt.Errorf("%w: already in network for a key not sent",
			controlplane.ErrRegistration)
	}
	result.SignInKeyUsed = signInUsed && err == nil
	return result, err
}

// freshNodeKeyCapability is register.freshnodekey1 (sign-in-moves-machine §4.1).
const freshNodeKeyCapability = "register.freshnodekey1"

// openRegistration opens the registration session. A browser sign-in with
// its own node key uses it when Core offers register.freshnodekey1; a Core
// without it keeps the profile's key, so signing back in to the same Device
// still works there.
func (c *Client) openRegistration(ctx context.Context, origin *url.URL, keys profileKeys,
	options controlplane.RegisterOptions,
) (*session, profileKeys, bool, error) {
	if len(options.SignInNodePrivateKey) != 0 && options.AuthKey == "" && options.ClusterJoin == nil {
		raw, err := controlplane.ParsePrivateKey(options.SignInNodePrivateKey)
		if err != nil {
			return nil, profileKeys{}, false, err
		}
		signIn, err := key.NodePrivateFromBytes(raw[:])
		clear(raw[:])
		if err != nil {
			return nil, profileKeys{}, false, controlplane.ErrInvalidMaterial
		}
		signInKeys := keys
		signInKeys.node = signIn
		public := signIn.Public()
		s, err := c.open(ctx, origin, sessionOptions{
			machine: keys.machine, control: keys.control,
			nodeKey: public[:], version: options.Version,
			capabilities: append([]string{freshNodeKeyCapability}, siblingCapabilities(options)...),
		})
		if err != nil {
			return nil, profileKeys{}, false, err
		}
		if slices.Contains(s.reply.GetCapabilities(), freshNodeKeyCapability) {
			return s, signInKeys, true, nil
		}
		s.close()
	}
	nodePublic := keys.node.Public()
	s, err := c.open(ctx, origin, sessionOptions{
		machine: keys.machine, control: keys.control,
		nodeKey: nodePublic[:], version: options.Version, capabilities: siblingCapabilities(options),
	})
	return s, keys, false, err
}

// registrationAuth chooses the method: an enrollment key, a resumed
// approval (its handle is the URL token, mtcp-v1 §6.2), or a new one.
func registrationAuth(origin *url.URL, options controlplane.RegisterOptions) (*mtcpv1.RegisterRequest_Auth, error) {
	if options.ClusterJoin != nil {
		if options.AuthKey != "" || options.FollowupURL != "" {
			return nil, fmt.Errorf("%w: a cluster join takes no other method", controlplane.ErrRegistration)
		}
		return clusterJoinAuth(options.ClusterJoin)
	}
	if options.AuthKey != "" {
		if options.FollowupURL != "" {
			return nil, fmt.Errorf("%w: an enrollment key and a follow-up are exclusive", controlplane.ErrRegistration)
		}
		return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_EnrollmentKey{
			EnrollmentKey: options.AuthKey,
		}}, nil
	}
	handle := ""
	if options.FollowupURL != "" {
		followup, err := url.Parse(options.FollowupURL)
		if err != nil || followup.Scheme != "https" || followup.Hostname() != origin.Hostname() ||
			(followup.Port() != "" && followup.Port() != origin.Port()) ||
			!strings.HasPrefix(followup.EscapedPath(), approvalPath) || followup.RawQuery != "" ||
			followup.Fragment != "" {
			return nil, fmt.Errorf("%w: the approval URL is not on the control origin", controlplane.ErrRegistration)
		}
		handle = strings.TrimPrefix(followup.EscapedPath(), approvalPath)
		if handle == "" || strings.Contains(handle, "/") {
			return nil, fmt.Errorf("%w: malformed approval URL", controlplane.ErrRegistration)
		}
	}
	return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_Interactive{
		Interactive: &mtcpv1.RegisterRequest_Interactive{ResumeHandle: handle},
	}}, nil
}

// registerRequest proves possession of the node key and of a disco key
// for this session. The disco key is used only for the proof: each map
// session reports its own (mtcp-v1 §8.1).
func registerRequest(s *session, keys profileKeys, options controlplane.RegisterOptions,
	auth *mtcpv1.RegisterRequest_Auth,
) (*mtcpv1.RegisterRequest, error) {
	nodeProof, discoKey, discoProof, err := proveKeys(s, keys.node)
	if err != nil {
		return nil, err
	}
	nodePublic := keys.node.Public()
	return &mtcpv1.RegisterRequest{
		NodeKey: nodePublic[:], NodeKeyProof: nodeProof, DiscoKey: discoKey, DiscoKeyProof: discoProof,
		Hostinfo: &mtcpv1.Hostinfo{
			Hostname: options.Hostname, Os: runtime.GOOS, Arch: runtime.GOARCH,
			ClientVersion: options.Version,
		},
		Auth: auth,
	}, nil
}

// proveKeys returns the node key proof and a fresh disco key with its
// proof, bound to the session (mtcp-v1 §6.4).
func proveKeys(s *session, node key.NodePrivate) ([]byte, []byte, []byte, error) {
	hash := s.noise.HandshakeHash()
	nodeProof, err := sharedmtcp.NodeKeyProof(node, s.control, hash)
	if err != nil {
		return nil, nil, nil, controlplane.ErrInvalidMaterial
	}
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		return nil, nil, nil, err
	}
	discoProof, err := sharedmtcp.DiscoKeyProof(disco, s.control, hash)
	if err != nil {
		return nil, nil, nil, err
	}
	discoPublic := disco.Public()
	return nodeProof[:], discoPublic[:], discoProof[:], nil
}

// awaitRegistration reads until the RegisterResponse. A pending approval
// is reported at once, or after wait if Core may still approve it on this
// session.
func awaitRegistration(ctx context.Context, s *session, wait time.Duration, join bool,
	classify func(*mtcpv1.Error) error, coreNow func() time.Time,
) (controlplane.RegistrationResult, error) {
	var pending *controlplane.RegistrationResult
	deadline := time.Now().Add(answerTimeout)
	for {
		if pending != nil && !time.Now().Before(deadline) {
			return *pending, nil
		}
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			if pending != nil {
				return *pending, nil
			}
			return controlplane.RegistrationResult{}, temporary(err)
		}
		switch m := message.(type) {
		case *mtcpv1.RegisterResponse:
			result, done, err := registrationOutcome(m, join, coreNow())
			if err != nil || done {
				return result, err
			}
			if wait <= 0 {
				return result, nil
			}
			pending = &result
			deadline = time.Now().Add(wait)
			if result.Approval != nil {
				// The expiry is by Core's clock; the deadline by this one.
				if local := time.Now().Add(result.Approval.ExpiresAt.Sub(coreNow())); local.Before(deadline) {
					deadline = local
				}
			}
		case *mtcpv1.Error:
			return controlplane.RegistrationResult{}, classify(m)
		}
	}
}

// registrationOutcome reads a RegisterResponse; coreNow is the time by
// Core's clock, which an approval's expiry is in.
func registrationOutcome(response *mtcpv1.RegisterResponse, join bool, coreNow time.Time,
) (controlplane.RegistrationResult, bool, error) {
	pending := response.GetPending()
	switch {
	case pending != nil && join != (pending.GetAdminApproval() != nil):
		// A cluster join waits for an administrator, anything else for a
		// browser.
		return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: unexpected pending answer",
			controlplane.ErrRegistration)
	case response.GetAuthorized() != nil:
		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, true, nil
	case join && pending != nil:
		result, err := adminApprovalOutcome(pending, coreNow)
		return result, err != nil, err
	case response.GetPending() != nil:
		approval := response.GetPending().GetApprovalUrl()
		if parsed, err := url.Parse(approval); err != nil || parsed.Scheme != "https" || len(approval) > 512 {
			return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: invalid approval URL", controlplane.ErrRegistration)
		}
		return controlplane.RegistrationResult{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: approval,
		}, false, nil
	case response.GetAlreadyInNetwork() != nil:
		if join {
			return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: unexpected already in network",
				controlplane.ErrRegistration)
		}
		sibling := response.GetAlreadyInNetwork().GetSiblingMachineKey()
		if len(sibling) != key.Size || [key.Size]byte(sibling) == ([key.Size]byte{}) {
			return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: malformed already in network",
				controlplane.ErrRegistration)
		}
		return controlplane.RegistrationResult{
			State: controlplane.RegistrationStateAlreadyInNetwork, SiblingMachineKey: [key.Size]byte(sibling),
		}, true, nil
	case response.GetRejected() != nil:
		rejected := &controlplane.RejectedError{
			Code:    strings.ToLower(response.GetRejected().GetCode().String()),
			Message: boundedText(response.GetRejected().GetMessage()),
		}
		// K1.1: a join whose keys hold a request with other signing
		// material gets that request back, to print its own code.
		if join && response.GetRejected().GetCode() == mtcpv1.RegisterResponse_Rejected_CONFLICT &&
			response.GetRejected().GetAdminApproval() != nil {
			approval, err := conflictApproval(response.GetRejected().GetAdminApproval())
			if err != nil {
				return controlplane.RegistrationResult{}, true, err
			}
			rejected.Approval = approval
		}
		return controlplane.RegistrationResult{}, true, rejected
	default:
		return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: empty response", controlplane.ErrRegistration)
	}
}

// RotateNodeKey replaces the Device's node key over a session that the
// current node key opens (mtcp-v1 §6.3). The caller stages the new key
// durably first; repeating a committed rotation succeeds.
func (c *Client) RotateNodeKey(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	newNodePrivateKey []byte, options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	keys, err := c.openKeys(material)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	newRaw, err := controlplane.ParsePrivateKey(newNodePrivateKey)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	defer clear(newRaw[:])
	newNode, err := key.NodePrivateFromBytes(newRaw[:])
	if err != nil {
		return controlplane.RegistrationResult{}, controlplane.ErrInvalidMaterial
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	if err := c.checkPinned(ctx, origin, keys.control, options.PinnedFingerprint); err != nil {
		return controlplane.RegistrationResult{}, err
	}
	oldPublic := keys.node.Public()
	s, err := c.open(ctx, origin, sessionOptions{
		machine: keys.machine, control: keys.control,
		nodeKey: oldPublic[:], version: options.Version, prove: c.gatewayProof(keys.node),
	})
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	defer s.close()
	// A session is established by a Ping or a RegisterRequest (mtcp-v1 §3).
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
		return controlplane.RegistrationResult{}, temporary(err)
	}
	nodeProof, discoKey, discoProof, err := proveKeys(s, newNode)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	newPublic := newNode.Public()
	if err := s.send(sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{
		NewNodeKey:   newPublic[:],
		NodeKeyProof: nodeProof, NewDiscoKey: discoKey, DiscoKeyProof: discoProof,
		ServiceAccountToken: options.GatewayToken.Reveal(),
	}); err != nil {
		return controlplane.RegistrationResult{}, temporary(err)
	}
	deadline := time.Now().Add(answerTimeout)
	for {
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			return controlplane.RegistrationResult{}, temporary(err)
		}
		switch m := message.(type) {
		case *mtcpv1.RotateNodeKeyResponse:
			if string(m.GetNodeKey()) != string(newPublic[:]) {
				return controlplane.RegistrationResult{}, fmt.Errorf("%w: rotation answered another key",
					controlplane.ErrRegistration)
			}
			return controlplane.RegistrationResult{
				State:             controlplane.RegistrationStateAuthorized,
				MachineAuthorized: true,
			}, nil
		case *mtcpv1.Error:
			if m.GetCode() == mtcpv1.Error_NOT_PERMITTED {
				// Definitive: Core answers a repeat of a committed rotation
				// with success, so this one was not applied (mtcp-v1 §6.3).
				return controlplane.RegistrationResult{}, fmt.Errorf("%w: %s",
					controlplane.ErrNodeKeyRotationRefused, boundedText(m.GetMessage()))
			}
			return controlplane.RegistrationResult{}, c.sessionError(m)
		}
		// Map messages for the old key arrive meanwhile and are not needed.
	}
}

// signOutCapability is device.signout1: Logout.keep_device keeps the Device
// and Core answers LogoutResponse (mtcp-v1 §6.5).
const signOutCapability = "device.signout1"

// Logout ends the Device over a session that its current keys open
// (mtcp-v1 §6.5): Core revokes the Device and its keys and answers
// Lifecycle{LOGGED_OUT}. Logout carries the session proof of the node key,
// so an expired Device, which has no map stream, logs out too
// (TD-CORE-145). Keys Core proves were removed with their Device are told
// REVOKED: that wraps controlplane.ErrDeviceRemoved and the node may erase
// them. Core refusing the keys (NOT_AUTHORIZED) wraps
// controlplane.ErrDeviceNotAuthorized: the cause is ambiguous, so the node
// keeps them (TD-CLI-100).
func (c *Client) Logout(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) error {
	return c.logout(ctx, controlURL, material, options, false)
}

// SignOut signs the Device out and keeps it (device.signout1, schema 283):
// nil once Core answers LogoutResponse{SIGNED_OUT}, and the node keeps its
// keys; its owner signs in again on this installation to bring it back.
// Without the capability nothing is sent and the error wraps
// controlplane.ErrSignOutUnsupported. REMOVED (an ephemeral Device, or keys
// removed before) wraps controlplane.ErrDeviceRemoved; a Workspace Device's
// refusal wraps controlplane.ErrSignOutNotPermitted.
func (c *Client) SignOut(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) error {
	return c.logout(ctx, controlURL, material, options, true)
}

func (c *Client) logout(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	options controlplane.RegisterOptions, keep bool,
) error {
	keys, err := c.openKeys(material)
	if err != nil {
		return err
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return err
	}
	if err := c.checkPinned(ctx, origin, keys.control, options.PinnedFingerprint); err != nil {
		return err
	}
	nodePublic := keys.node.Public()
	s, err := c.open(ctx, origin, sessionOptions{
		machine: keys.machine, control: keys.control,
		nodeKey: nodePublic[:], version: options.Version, prove: c.gatewayProof(keys.node),
		capabilities: []string{signOutCapability},
	})
	if err != nil {
		return err
	}
	defer s.close()
	answers := slices.Contains(s.reply.GetCapabilities(), signOutCapability)
	if keep && !answers {
		// An older Core would remove the Device: ask nothing.
		return controlplane.ErrSignOutUnsupported
	}
	// A session is established by a Ping or a RegisterRequest (mtcp-v1 §3).
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
		return revokedOr(ctx, s, temporary(err))
	}
	proof, err := sharedmtcp.NodeKeySessionProof(keys.node, s.control, s.noise.HandshakeHash())
	if err != nil {
		return controlplane.ErrInvalidMaterial
	}
	if err := s.send(sharedmtcp.MessageLogout, &mtcpv1.Logout{NodeKeyProof: proof[:], KeepDevice: keep}); err != nil {
		return revokedOr(ctx, s, temporary(err))
	}
	deadline := time.Now().Add(answerTimeout)
	for {
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			// The answer may have been lost after Core logged the Device out;
			// asking again is safe: Core then answers REVOKED for these keys,
			// or SIGNED_OUT again for a Device it kept.
			return temporary(err)
		}
		switch m := message.(type) {
		case *mtcpv1.LogoutResponse:
			switch m.GetOutcome() {
			case mtcpv1.LogoutResponse_SIGNED_OUT:
				if keep {
					return nil
				}
				return fmt.Errorf("%w: Core kept a Device asked to be removed", controlplane.ErrRegistration)
			case mtcpv1.LogoutResponse_REMOVED:
				if keep {
					return fmt.Errorf("%w: Core removed the Device", controlplane.ErrDeviceRemoved)
				}
				return nil
			}
			return fmt.Errorf("%w: unknown logout outcome", controlplane.ErrRegistration)
		case *mtcpv1.Lifecycle:
			// REVOKED proves these exact keys were removed with their Device
			// (mtcp-v1 §10), whoever sends it: the map stream may tell it
			// before Logout is read and then end the session.
			if m.GetState() == mtcpv1.Lifecycle_REVOKED {
				return fmt.Errorf("%w: %s", controlplane.ErrDeviceRemoved, boundedText(m.GetReason()))
			}
			if answers {
				// device.signout1: only LogoutResponse answers Logout.
				continue
			}
			if m.GetState() == mtcpv1.Lifecycle_LOGGED_OUT {
				return nil
			}
			// EXPIRED and the rest describe the session before Core read the
			// Logout (an expired Device is told EXPIRED on connect): wait for
			// the answer.
		case *mtcpv1.Error:
			switch m.GetCode() {
			case mtcpv1.Error_NOT_AUTHORIZED:
				return fmt.Errorf("%w: %s", controlplane.ErrDeviceNotAuthorized, boundedText(m.GetMessage()))
			case mtcpv1.Error_NOT_PERMITTED:
				if keep {
					return fmt.Errorf("%w: %s", controlplane.ErrSignOutNotPermitted, boundedText(m.GetMessage()))
				}
			}
			return c.sessionError(m)
		}
		// Map messages for the session are not needed.
	}
}

// revokedOr reads what Core sent before a send failed: the map stream may
// have told REVOKED for these keys and ended the session. Otherwise fallback.
func revokedOr(ctx context.Context, s *session, fallback error) error {
	deadline := time.Now().Add(time.Second)
	for {
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			return fallback
		}
		if m, ok := message.(*mtcpv1.Lifecycle); ok && m.GetState() == mtcpv1.Lifecycle_REVOKED {
			return fmt.Errorf("%w: %s", controlplane.ErrDeviceRemoved, boundedText(m.GetReason()))
		}
	}
}

// receiveUntil returns the next message before deadline or ctx ends.
func (s *session) receiveUntil(ctx context.Context, deadline time.Time) (proto.Message, error) {
	type result struct {
		message proto.Message
		err     error
	}
	done := make(chan result, 1)
	go func() {
		_, message, err := s.receive()
		done <- result{message, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-done:
		return r.message, r.err
	case <-ctx.Done():
		s.close()
		<-done
		return nil, ctx.Err()
	case <-timer.C:
		s.close()
		<-done
		return nil, context.DeadlineExceeded
	}
}

// sessionError classifies an Error from Core.
func sessionError(m *mtcpv1.Error) error {
	switch m.GetCode() {
	case mtcpv1.Error_INTERNAL, mtcpv1.Error_OVERLOADED:
		return fmt.Errorf("%w: %s", controlplane.ErrRegistrationTemporary, boundedText(m.GetMessage()))
	default:
		return fmt.Errorf("%w: %s (%s)", controlplane.ErrRegistration, strings.ToLower(m.GetCode().String()),
			boundedText(m.GetMessage()))
	}
}

func temporary(err error) error {
	if errors.Is(err, controlplane.ErrRegistration) {
		return err
	}
	return fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
}

// boundedText keeps server text short and printable for logs.
// boundedText is Core's message as the apps may show it: without control or
// format characters (bidi overrides could disguise it), at most 300 bytes, cut
// on a character boundary.
func boundedText(text string) string {
	const limit = 300
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, text)
	if len(cleaned) <= limit {
		return cleaned
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(cleaned[cut]) {
		cut--
	}
	return cleaned[:cut]
}
