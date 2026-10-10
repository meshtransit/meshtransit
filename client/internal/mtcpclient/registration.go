package mtcpclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"time"

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
	auth, err := registrationAuth(origin, options)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	if err := c.checkPinned(ctx, origin, keys.control, options.PinnedFingerprint); err != nil {
		return controlplane.RegistrationResult{}, err
	}
	nodePublic := keys.node.Public()
	s, err := c.open(ctx, origin, sessionOptions{
		machine: keys.machine, control: keys.control,
		nodeKey: nodePublic[:], version: options.Version,
	})
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	defer s.close()
	request, err := registerRequest(s, keys, options, auth)
	if err != nil {
		return controlplane.RegistrationResult{}, err
	}
	if err := s.send(sharedmtcp.MessageRegisterRequest, request); err != nil {
		return controlplane.RegistrationResult{}, temporary(err)
	}
	wait := time.Duration(0)
	if options.FollowupURL != "" {
		wait = followupWait
	}
	return awaitRegistration(ctx, s, wait)
}

// registrationAuth chooses the method: an enrollment key, a resumed
// approval (its handle is the URL token, mtcp-v1 §6.2), or a new one.
func registrationAuth(origin *url.URL, options controlplane.RegisterOptions) (*mtcpv1.RegisterRequest_Auth, error) {
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
func awaitRegistration(ctx context.Context, s *session, wait time.Duration) (controlplane.RegistrationResult, error) {
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
			result, done, err := registrationOutcome(m)
			if err != nil || done {
				return result, err
			}
			if wait <= 0 {
				return result, nil
			}
			pending = &result
			deadline = time.Now().Add(wait)
		case *mtcpv1.Error:
			return controlplane.RegistrationResult{}, sessionError(m)
		}
	}
}

func registrationOutcome(response *mtcpv1.RegisterResponse) (controlplane.RegistrationResult, bool, error) {
	switch {
	case response.GetAuthorized() != nil:
		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, true, nil
	case response.GetPending() != nil:
		approval := response.GetPending().GetApprovalUrl()
		if parsed, err := url.Parse(approval); err != nil || parsed.Scheme != "https" || len(approval) > 512 {
			return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: invalid approval URL", controlplane.ErrRegistration)
		}
		return controlplane.RegistrationResult{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: approval,
		}, false, nil
	case response.GetRejected() != nil:
		return controlplane.RegistrationResult{}, true, fmt.Errorf("%w: %s (%s)", controlplane.ErrRegistration,
			strings.ToLower(response.GetRejected().GetCode().String()), boundedText(response.GetRejected().GetMessage()))
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
		nodeKey: oldPublic[:], version: options.Version,
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
			return controlplane.RegistrationResult{}, sessionError(m)
		}
		// Map messages for the old key arrive meanwhile and are not needed.
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
func boundedText(text string) string {
	const limit = 200
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	if len(cleaned) > limit {
		cleaned = cleaned[:limit]
	}
	return cleaned
}
