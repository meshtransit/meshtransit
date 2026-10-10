package mtcptest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// Registration is what RegisterResponse{authorized} reports (mtcp-v1 §6.2).
type Registration struct {
	DeviceID  string
	NetworkID string
	Addresses []netip.Addr
	KeyExpiry time.Time
}

// Register opens a session, submits one enrollment-key RegisterRequest with
// proofs of possession of the node and disco keys, and waits for the
// authorized response and the first map that follows it on the same
// session (mtcp-v1 §6). A replay with the same keys must be answered with
// the same authorization.
func (client *Client) Register(ctx context.Context, credential string) (_ Registration, resultErr error) {
	if ctx == nil || client == nil || !validCredential(credential) {
		return Registration{}, ErrInvalidClient
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	nodePublic := client.node.Public()
	s, err := client.openSession(operationCtx, nodePublic[:])
	if err != nil {
		return Registration{}, errors.Join(ErrRegistration, err)
	}
	defer func() { resultErr = errors.Join(resultErr, s.close()) }()
	request, err := client.registerRequest(s, credential)
	if err != nil {
		return Registration{}, errors.Join(ErrRegistration, err)
	}
	if err := s.send(sharedmtcp.MessageRegisterRequest, request); err != nil {
		return Registration{}, errors.Join(ErrRegistration, fmt.Errorf("send registration: %w", err))
	}
	registration, err := awaitAuthorization(operationCtx, s)
	if err != nil {
		return Registration{}, errors.Join(ErrRegistration, err)
	}
	if err := awaitFirstMap(operationCtx, s, registration, nodePublic); err != nil {
		return Registration{}, errors.Join(ErrRegistration, err)
	}
	return registration, nil
}

// registerRequest proves possession of the node and disco keys, bound to
// this session's handshake (mtcp-v1 §6.4).
func (client *Client) registerRequest(s *session, credential string) (*mtcpv1.RegisterRequest, error) {
	hash := s.noise.HandshakeHash()
	nodeProof, err := sharedmtcp.NodeKeyProof(client.node, s.control, hash)
	if err != nil {
		return nil, fmt.Errorf("prove node key: %w", err)
	}
	discoProof, err := sharedmtcp.DiscoKeyProof(client.disco, s.control, hash)
	if err != nil {
		return nil, fmt.Errorf("prove disco key: %w", err)
	}
	nodePublic, discoPublic := client.node.Public(), client.disco.Public()
	return &mtcpv1.RegisterRequest{
		NodeKey: nodePublic[:], NodeKeyProof: nodeProof[:],
		DiscoKey: discoPublic[:], DiscoKeyProof: discoProof[:],
		Hostinfo: &mtcpv1.Hostinfo{Hostname: client.hostname, Os: runtime.GOOS, Arch: runtime.GOARCH,
			ClientVersion: "0"},
		Auth: &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_EnrollmentKey{
			EnrollmentKey: credential,
		}},
	}, nil
}

// awaitAuthorization reads until the RegisterResponse. Anything but
// authorized is a failure: the test credential never needs an approval.
func awaitAuthorization(ctx context.Context, s *session) (Registration, error) {
	for {
		message, err := s.receive(ctx)
		if err != nil {
			return Registration{}, fmt.Errorf("read registration response: %w", err)
		}
		switch m := message.(type) {
		case *mtcpv1.RegisterResponse:
			return authorization(m)
		case *mtcpv1.Error:
			return Registration{}, errorMessage(m)
		case *mtcpv1.Lifecycle:
			return Registration{}, fmt.Errorf("control sent lifecycle %v before authorizing", m.GetState())
		default:
			return Registration{}, fmt.Errorf("unexpected %T before the registration response", message)
		}
	}
}

func authorization(response *mtcpv1.RegisterResponse) (Registration, error) {
	switch {
	case response.GetRejected() != nil:
		return Registration{}, fmt.Errorf("registration rejected: %v", response.GetRejected().GetCode())
	case response.GetPending() != nil:
		return Registration{}, errors.New("registration unexpectedly needs an approval")
	case response.GetAuthorized() == nil:
		return Registration{}, errors.New("registration response has no outcome")
	}
	authorized := response.GetAuthorized()
	registration := Registration{DeviceID: authorized.GetDeviceId(), NetworkID: authorized.GetNetworkId()}
	if authorized.GetKeyExpiryMs() != 0 {
		registration.KeyExpiry = time.UnixMilli(authorized.GetKeyExpiryMs()).UTC()
	}
	for _, raw := range authorized.GetAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok {
			return Registration{}, errors.New("authorized registration carries a malformed address")
		}
		registration.Addresses = append(registration.Addresses, address.Unmap())
	}
	if registration.DeviceID == "" || registration.NetworkID == "" || len(registration.Addresses) == 0 {
		return Registration{}, errors.New("authorized registration is incomplete")
	}
	return registration, nil
}

// awaitFirstMap checks that the map stream starts on the registration
// session with the registered Device (mtcp-v1 §6.2, §11).
func awaitFirstMap(ctx context.Context, s *session, registration Registration, nodeKey [32]byte) error {
	for {
		message, err := s.receive(ctx)
		if err != nil {
			return fmt.Errorf("read first map: %w", err)
		}
		switch m := message.(type) {
		case *mtcpv1.KeyUpdate:
			if err := s.acknowledgeKeys(m); err != nil {
				return err
			}
		case *mtcpv1.MapSnapshot:
			state := newMapState()
			update, err := state.applySnapshot(m)
			if err != nil {
				return err
			}
			self := update.Map
			if self.DeviceID != registration.DeviceID || self.NodeKey != nodeKey ||
				self.KeyExpiry != registration.KeyExpiry || !slices.EqualFunc(self.Addresses, registration.Addresses,
				func(prefix netip.Prefix, address netip.Addr) bool { return prefix.Addr() == address }) {
				return errors.New("first map does not describe the authorized Device")
			}
			return nil
		case *mtcpv1.RelayTicket, *mtcpv1.Pong, *mtcpv1.Notice:
		case *mtcpv1.Error:
			return errorMessage(m)
		case *mtcpv1.Lifecycle:
			return fmt.Errorf("control sent lifecycle %v instead of the first map", m.GetState())
		default:
			return fmt.Errorf("unexpected %T before the first map", message)
		}
	}
}
