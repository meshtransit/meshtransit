package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/adapter/flowloginternal"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/key"
)

// flowLogCacheNetworks bounds the Networks whose connection log settings a
// replica remembers: an entry is about 100 bytes, so a replica serving many
// small Networks (Cloud) keeps them all.
const flowLogCacheNetworks = 1 << 17

var errInvalidFlowTicketComposition = errors.New("invalid connection log ticket composition")

// composeFlowTickets builds the signer of nodes' connection log tokens and
// the shared reader of their Networks' settings (connection logs design
// §16b C26, C27). Only the current signing key signs; the next one is for
// the receiver to learn (s4c). The keys sign nothing else (flowlog-v1 §3):
// one shared with the relay authority is refused.
func composeFlowTickets(ctx context.Context, cfg config.FlowTicketConfig, relay *config.RelayAuthorityConfig,
	sessions *mapsession.Service,
) (*mtcpadapter.FlowSigner, mapsession.FlowLogReader, error) {
	if sessions == nil {
		return nil, nil, errInvalidFlowTicketComposition
	}
	reader, ok := sessions.FlowLogs()
	if !ok {
		return nil, nil, errInvalidFlowTicketComposition
	}
	signing, next, err := cfg.SigningKeys(ctx)
	if err != nil {
		return nil, nil, errors.Join(errInvalidFlowTicketComposition, err)
	}
	if relay != nil {
		relaySigning, relayNext, err := relay.SigningKeys(ctx)
		if err != nil {
			return nil, nil, errors.Join(errInvalidFlowTicketComposition, err)
		}
		if sharesSigningKey([]*key.SigningPrivate{&signing, next}, []*key.SigningPrivate{&relaySigning, relayNext}) {
			return nil, nil, errFlowSigningKeyShared
		}
	}
	public := signing.Public()
	signer, err := mtcpadapter.NewFlowSigner(signing, ed25519.PublicKey(public[:]), cfg.Deployment, cfg.ReceiverKey,
		time.Now)
	if err != nil {
		return nil, nil, errors.Join(errInvalidFlowTicketComposition, err)
	}
	cache, err := mapsession.NewFlowLogCache(reader, flowLogCacheNetworks, time.Now)
	if err != nil {
		return nil, nil, errors.Join(errInvalidFlowTicketComposition, err)
	}
	return signer, cache, nil
}

var errFlowSigningKeyShared = errors.New("the connection log signing key is also a relay authority key")

// sharesSigningKey reports a public key both lists hold.
func sharesSigningKey(left, right []*key.SigningPrivate) bool {
	for _, one := range left {
		for _, other := range right {
			if one != nil && other != nil && one.Public() == other.Public() {
				return true
			}
		}
	}
	return false
}

// flowReportCapabilities offers flow.report1 when Core signs tickets.
func flowReportCapabilities(signer *mtcpadapter.FlowSigner) []string {
	if signer == nil {
		return nil
	}
	return []string{mtcpadapter.CapabilityFlowReport}
}

var errInvalidFlowLogInternalComposition = errors.New("invalid connection log internal API composition")

// composeFlowLogInternal builds the receiver's internal API listener
// (connection logs design §16c, s4c1a). On a process that also signs
// tokens (role all), the current public key must be the signer's.
func composeFlowLogInternal(ctx context.Context, cfg config.FlowLogInternalConfig, tickets *config.FlowTicketConfig,
	logger *slog.Logger,
) (*flowloginternal.Server, *flowloginternal.Metrics, error) {
	keys := make([]flowloginternal.TokenKey, 0, len(cfg.TokenKeys))
	var current ed25519.PublicKey
	for _, key := range cfg.TokenKeys {
		keys = append(keys, flowloginternal.TokenKey{State: key.State, Key: key.Key})
		if key.State == config.FlowTokenKeyCurrent {
			current = key.Key
		}
	}
	if tickets != nil {
		signing, _, err := tickets.SigningKeys(ctx)
		if err != nil {
			return nil, nil, errors.Join(errInvalidFlowLogInternalComposition, err)
		}
		public := signing.Public()
		if !current.Equal(ed25519.PublicKey(public[:])) {
			return nil, nil, errors.Join(errInvalidFlowLogInternalComposition,
				errors.New("the current token public key is not the signing key's"))
		}
	}
	metrics := flowloginternal.NewMetrics()
	server, err := flowloginternal.NewServer(flowloginternal.Options{
		Address: cfg.Address, CertFile: cfg.CertFile, KeyFile: cfg.KeyFile, ClientCAFile: cfg.ClientCAFile,
		ClientURI: cfg.ClientURI, TokenKeys: keys, Metrics: metrics, Logger: logger, Now: time.Now,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidFlowLogInternalComposition, err)
	}
	return server, metrics, nil
}
