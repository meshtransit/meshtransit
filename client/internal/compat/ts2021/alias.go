package ts2021

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"tailscale.com/tailcfg"
)

const (
	deviceAliasCapability tailcfg.NodeCapability = "https://meshtransit.io/cap/device-alias-v1"
	maxAliasDocumentBytes int                    = 8192
)

type aliasDocument struct {
	Version       uint64               `json:"version"`
	ContractID    string               `json:"contract_id"`
	EndpointID    string               `json:"endpoint_id"`
	Generation    uint64               `json:"generation"`
	GrantRevision uint64               `json:"grant_revision"`
	RecoveryEpoch uint64               `json:"recovery_epoch"`
	SelfKey       string               `json:"self_key"`
	PeerKey       string               `json:"peer_key"`
	Role          networkmap.AliasRole `json:"role"`
	ExpiresAt     time.Time            `json:"expires_at"`
	Services      []aliasService       `json:"services"`
}

type aliasService struct {
	Protocol uint8  `json:"protocol"`
	PortFrom uint16 `json:"port_from"`
	PortTo   uint16 `json:"port_to"`
}

func convertAlias(node *tailcfg.Node) (*networkmap.AliasBinding, error) {
	documents, present := node.CapMap[deviceAliasCapability]
	hasAlias := node.SelfNodeV4MasqAddrForThisPeer != nil || node.SelfNodeV6MasqAddrForThisPeer != nil
	if !present && !hasAlias {
		return nil, nil
	}
	if !present || !hasAlias || len(documents) != 1 {
		return nil, fmt.Errorf("%w: alias fields require one versioned grant", ErrNetmapInvalid)
	}
	body := []byte(documents[0])
	if len(body) == 0 || len(body) > maxAliasDocumentBytes {
		return nil, fmt.Errorf("%w: alias document exceeds limit", ErrNetmapInvalid)
	}
	if err := rejectDuplicateAliasKeys(json.NewDecoder(bytes.NewReader(body)), 0); err != nil {
		return nil, fmt.Errorf("%w: alias document shape is invalid", ErrNetmapInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var document aliasDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: alias document is invalid", ErrNetmapInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || document.Version != 1 {
		return nil, fmt.Errorf("%w: alias document version or trailing value is invalid", ErrNetmapInvalid)
	}
	var ipv4, ipv6 netip.Addr
	if node.SelfNodeV4MasqAddrForThisPeer != nil {
		ipv4 = *node.SelfNodeV4MasqAddrForThisPeer
	}
	if node.SelfNodeV6MasqAddrForThisPeer != nil {
		ipv6 = *node.SelfNodeV6MasqAddrForThisPeer
	}
	services := make([]networkmap.AliasService, 0, len(document.Services))
	for _, service := range document.Services {
		services = append(services, networkmap.AliasService{
			Protocol: service.Protocol,
			PortFrom: service.PortFrom,
			PortTo:   service.PortTo,
		})
	}
	return &networkmap.AliasBinding{
		ContractID:    document.ContractID,
		EndpointID:    document.EndpointID,
		Generation:    document.Generation,
		GrantRevision: document.GrantRevision,
		RecoveryEpoch: document.RecoveryEpoch,
		SelfKey:       document.SelfKey,
		PeerKey:       document.PeerKey,
		Role:          document.Role,
		SelfIPv4:      ipv4,
		SelfIPv6:      ipv6,
		ExpiresAt:     document.ExpiresAt.UTC(),
		Services:      services,
	}, nil
}

// The standard JSON decoder accepts duplicate keys. Reject those before
// decoding any authority-bearing fields, including duplicates inside services.
func rejectDuplicateAliasKeys(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("alias nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return errors.New("alias root must be an object")
		}
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("alias object key is invalid")
			}
			if !aliasDocumentKey(key, depth) {
				return errors.New("alias object key is unknown or has invalid case")
			}
			if _, exists := seen[key]; exists {
				return errors.New("alias object key is duplicated")
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateAliasKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		if depth == 0 {
			return errors.New("alias root must be an object")
		}
		for decoder.More() {
			if err := rejectDuplicateAliasKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("alias container is invalid")
	}
	_, err = decoder.Token()
	return err
}

// JSON field matching must be exact. encoding/json otherwise accepts casing
// variants that can override the same authority field under a second spelling.
func aliasDocumentKey(key string, depth int) bool {
	switch depth {
	case 0:
		switch key {
		case "version", "contract_id", "endpoint_id", "generation", "grant_revision", "recovery_epoch",
			"self_key", "peer_key", "role", "expires_at", "services":
			return true
		}
	case 2:
		switch key {
		case "protocol", "port_from", "port_to":
			return true
		}
	}
	return false
}
