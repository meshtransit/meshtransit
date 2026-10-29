package daemon

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubecert"
	"meshtransit.net/client/internal/networkmap"
)

// A call reaches a session that holds a map within
// gatewayCertificateHandoff, or is never sent (its Deadline). Once taken,
// gatewayCertificateAnswerWait outlasts the stream's own 20-second wait, so
// the stream times out first and keeps a late answer for the next call
// (a4b2 review M1).
const (
	gatewayCertificateHandoff    = 5 * time.Second
	gatewayCertificateAnswerWait = 22 * time.Second
)

// gatewayCertificates is a Kubernetes gateway's replica certificate: the
// manager that keeps it and the channel its map streams take calls from.
type gatewayCertificates struct {
	manager *kubecert.Manager
	calls   chan controlplane.KubeCertCall
	done    sync.WaitGroup

	// mu guards the last certificate converted for TLS, by serial and
	// issuer.
	mu        sync.Mutex
	tls       *tls.Certificate
	tlsSerial [16]byte
	tlsIssuer [32]byte
	// tlsIssuedAt is when the converted certificate was taken.
	tlsIssuedAt time.Time
}

// GatewayCertificateStatus is a gateway's certificate as status shows it:
// never a key, a token or the certificate itself.
type GatewayCertificateStatus struct {
	HasCertificate bool
	Serial         string // hex
	Issuer         string // the issuer's SHA-256, hex
	Root           string // the root's SHA-256, hex
	NotAfter       time.Time
	RenewAt        time.Time // Core's clock
	// MapMismatch: the map names CAs other than the certificate's.
	MapMismatch bool
	// WaitingSince is when the request waiting for Core was made (Core's
	// clock); zero: none waits. WaitingFor is how long it has waited.
	WaitingSince time.Time
	WaitingFor   time.Duration
	// Requests counts Core's answers by "outcome/reason".
	Requests map[string]uint64
}

// newGatewayCertificates builds the manager of a gateway that asks for its
// certificate (Options.GatewayCertificates).
func newGatewayCertificates(s *Service) (*gatewayCertificates, error) {
	certificates := &gatewayCertificates{calls: make(chan controlplane.KubeCertCall)}
	manager, err := kubecert.New(kubecert.Options{
		Request: certificates.request,
		Token: func() (string, error) {
			token, err := ReadPodToken(s.gatewayTokenFile)
			return string(token), err
		},
		Now: s.coreNow, Logger: s.logger, RenewAfter: s.gatewayRenewAfter,
	})
	if err != nil {
		return nil, err
	}
	certificates.manager = manager
	return certificates, nil
}

// request hands one request to the map stream's session and waits for its
// answer; a call no session took in time is never sent later (its
// Deadline).
func (certificates *gatewayCertificates) request(ctx context.Context,
	request controlplane.KubeCertRequest,
) (controlplane.KubeCertResult, error) {
	reply := make(chan controlplane.KubeCertReply, 1)
	deadline := time.Now().Add(gatewayCertificateHandoff)
	handoff := time.NewTimer(gatewayCertificateHandoff)
	defer handoff.Stop()
	select {
	case certificates.calls <- controlplane.KubeCertCall{Request: request, Reply: reply, Deadline: deadline}:
	case <-ctx.Done():
		return controlplane.KubeCertResult{}, ctx.Err()
	case <-handoff.C:
		return controlplane.KubeCertResult{}, controlplane.ErrKubeCertSessionLost
	}
	timer := time.NewTimer(gatewayCertificateAnswerWait)
	defer timer.Stop()
	select {
	case answer := <-reply:
		return answer.Result, answer.Err
	case <-ctx.Done():
		return controlplane.KubeCertResult{}, ctx.Err()
	case <-timer.C:
		return controlplane.KubeCertResult{}, controlplane.ErrKubeCertTimeout
	}
}

// start runs the manager until ctx ends; stop waits for it.
func (certificates *gatewayCertificates) start(ctx context.Context) {
	certificates.done.Go(func() { _ = certificates.manager.Run(ctx) })
}

func (certificates *gatewayCertificates) stop() { certificates.done.Wait() }

// kubeCertCalls is the channel a gateway's map stream takes certificate
// calls from; nil when it asks for none.
func (s *Service) kubeCertCalls() <-chan controlplane.KubeCertCall {
	if s.certificates == nil {
		return nil
	}
	return s.certificates.calls
}

// gatewayMapApplied tells the certificate manager the CAs the gateway's
// latest map names (mtcp-v1 §7.10).
func (s *Service) gatewayMapApplied(snapshot networkmap.Snapshot) {
	if s.certificates != nil {
		s.certificates.manager.MapChanged(snapshot.KubernetesCA)
	}
}

// coreNow is Core's clock as the control client estimates it, else this
// host's.
func (s *Service) coreNow() time.Time {
	if clock, ok := s.prober.(interface{ CoreNow() time.Time }); ok {
		return clock.CoreNow()
	}
	return time.Now()
}

// gatewayCertificateStatus is the certificate part of status; nil when the
// gateway asks for none.
func (s *Service) gatewayCertificateStatus() *GatewayCertificateStatus {
	if s.certificates == nil {
		return nil
	}
	measured := s.certificates.manager.Snapshot()
	status := &GatewayCertificateStatus{
		HasCertificate: measured.HasCertificate, NotAfter: measured.NotAfter, RenewAt: measured.RenewAt,
		MapMismatch: measured.MapMismatch, WaitingSince: measured.WaitingSince, WaitingFor: measured.WaitingFor,
		Requests: make(map[string]uint64, len(measured.Requests)),
	}
	for key, count := range measured.Requests {
		status.Requests[key[0]+"/"+key[1]] = count
	}
	if measured.HasCertificate {
		status.Serial = hex.EncodeToString(measured.Serial[:])
		status.Issuer, status.Root = hex.EncodeToString(measured.Issuer[:]), hex.EncodeToString(measured.Root[:])
	}
	return status
}

// GatewayCertificate is the replica's certificate to serve kubectl with,
// while unexpired. One whose CAs the map no longer names is still served
// until its early renewal: the map names only the current pair, so closing
// on a mismatch would close every replica in each planned rotation (K1b
// b5b, design §3 as built). The *tls.Certificate is made once per
// certificate. False when the gateway has none valid.
func (s *Service) GatewayCertificate() (*tls.Certificate, bool) {
	if s.certificates == nil {
		return nil, false
	}
	return s.certificates.serving()
}

// serving converts the manager's certificate, reusing the last conversion.
func (certificates *gatewayCertificates) serving() (*tls.Certificate, bool) {
	current, ok := certificates.manager.Current()
	if !ok {
		return nil, false
	}
	certificates.mu.Lock()
	defer certificates.mu.Unlock()
	if certificates.tls != nil && (certificates.tlsSerial == current.Serial && certificates.tlsIssuer == current.Issuer ||
		certificates.tlsIssuedAt.After(current.IssuedAt)) {
		// The same one, or a newer one another handshake already took
		// (review b5b L4).
		return certificates.tls, true
	}
	chain := make([][]byte, 0, 1+len(current.Chain))
	chain = append(chain, current.DER)
	chain = append(chain, current.Chain...)
	certificates.tls = &tls.Certificate{Certificate: chain, PrivateKey: current.Key, Leaf: current.Leaf}
	certificates.tlsSerial, certificates.tlsIssuer, certificates.tlsIssuedAt = current.Serial, current.Issuer,
		current.IssuedAt
	return certificates.tls, true
}

// MapFreshAt is when Core last confirmed a gateway's applied map current,
// on this host's monotonic clock; zero: never.
func (s *Service) MapFreshAt() time.Time { return s.mapFreshAtValue() }
