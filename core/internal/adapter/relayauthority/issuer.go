package relayauthority

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// TicketLifetime is how long each relay ticket is valid (MTRP §6 allows up
// to 15 minutes). Nodes get a fresh one 5 minutes before expiry.
const TicketLifetime = mtrp.MaxTicketLifetime

// minTicketLifetime refuses a ticket so close to the node's authority
// deadline that it would expire before the node could use it.
const minTicketLifetime = time.Minute

var (
	// ErrNoRelayMap reports a grant requested before a relay map is signed.
	ErrNoRelayMap = errors.New("relayauthority: no relay map to grant")
	// ErrAuthorityEnding reports a node whose authority ends within a minute.
	ErrAuthorityEnding = errors.New("relayauthority: node authority ends too soon for a ticket")
)

// Issuer signs relay tickets and packages each node's Interchange grant:
// the signing keys, the signed relay map and the ticket. It implements
// mapsession.RelayAccess.
type Issuer struct {
	publisher  *Publisher
	deployment [16]byte
	now        func() time.Time
	random     io.Reader
}

// NewIssuer issues tickets naming deployment, signed with the publisher's key.
func NewIssuer(publisher *Publisher, id deployment.ID) (*Issuer, error) {
	if publisher == nil || !id.IsValid() {
		return nil, errors.New("relayauthority: invalid issuer")
	}
	return &Issuer{publisher: publisher, deployment: id.Bytes(), now: publisher.opts.Now, random: rand.Reader}, nil
}

// GrantRelayAccess implements mapsession.RelayAccess.
func (issuer *Issuer) GrantRelayAccess(_ context.Context, request mapsession.RelayGrantRequest) (mapsession.RelayGrant, error) {
	metrics := issuer.publisher.opts.Metrics
	grant, err := issuer.grant(request)
	if err != nil {
		metrics.tickets.WithLabelValues("failed").Inc()
		return mapsession.RelayGrant{}, err
	}
	metrics.tickets.WithLabelValues("issued").Inc()
	return grant, nil
}

func (issuer *Issuer) grant(request mapsession.RelayGrantRequest) (mapsession.RelayGrant, error) {
	relayMap, mapKey, err := issuer.publisher.mapForNetwork(request.Network)
	if err != nil {
		return mapsession.RelayGrant{}, err
	}
	now := issuer.now()
	notAfter := now.Add(TicketLifetime)
	if request.NotAfter.Before(notAfter) {
		notAfter = request.NotAfter
	}
	if notAfter.Sub(now) < minTicketLifetime {
		return mapsession.RelayGrant{}, ErrAuthorityEnding
	}
	ticket := mtrp.Ticket{
		IssuedAtMS: now.UnixMilli(),
		NotAfterMS: notAfter.UnixMilli(),
		Node:       key.NodePublic(request.NodeKey),
		Disco:      key.DiscoPublic(request.DiscoveryKey),
		Deployment: issuer.deployment,
		Zones:      make([]mtrp.Zone, 0, 1+len(request.TrustContracts)),
	}
	if _, err := io.ReadFull(issuer.random, ticket.ID[:]); err != nil {
		return mapsession.RelayGrant{}, err
	}
	ticket.Zones = append(ticket.Zones, mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: request.Network.Bytes()})
	for _, contract := range request.TrustContracts {
		ticket.Zones = append(ticket.Zones, mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: contract.Bytes()})
	}
	// Up to MaxZones zones fit an MTT1 ticket. More (a session that declared
	// relay.zones2) need MTT2, whose zone list the node sends the relay.
	// An MTT2 ticket comes with an MTT1 fallback naming its inline zones
	// (the Network and the 31 oldest contracts) for a relay not yet taking
	// MTT2.
	var signed, zones, fallback []byte
	if len(ticket.Zones) <= mtrp.MaxZones {
		signed, err = ticket.Sign(issuer.publisher.opts.Signer)
	} else {
		signed, zones, err = ticket.SignZones(issuer.publisher.opts.Signer)
		if err == nil {
			fallback, err = issuer.fallbackTicket(ticket)
		}
	}
	if err != nil {
		return mapsession.RelayGrant{}, err
	}
	payload, err := mtrp.InterchangeGrant{
		SigningKeys:    issuer.publisher.trustedKeys(now),
		RelayMap:       relayMap.body,
		Ticket:         signed,
		TicketNotAfter: notAfter,
		TicketZones:    zones,
		FallbackTicket: fallback,
	}.Marshal()
	if err != nil {
		return mapsession.RelayGrant{}, err
	}
	return mapsession.NewRelayGrantForMap(request, payload, notAfter, mapKey)
}

// fallbackTicket signs an MTT1 ticket for ticket's keys and lifetime that
// names the first MaxZones of its zones in canonical order.
func (issuer *Issuer) fallbackTicket(ticket mtrp.Ticket) ([]byte, error) {
	if _, err := io.ReadFull(issuer.random, ticket.ID[:]); err != nil {
		return nil, err
	}
	sorted := slices.SortedFunc(slices.Values(ticket.Zones), mtrp.CompareZones)
	ticket.Zones = sorted[:mtrp.MaxZones]
	return ticket.Sign(issuer.publisher.opts.Signer)
}

// RelayMapCurrent implements mapsession.RelayMapFreshness.
func (issuer *Issuer) RelayMapCurrent(id network.ID, mapKey string) bool {
	return issuer.publisher.RelayMapCurrent(id, mapKey)
}
