package selfhost

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"meshtransit.net/shared/key"
)

// PublicKeys are the public halves render publishes: the relay's mtrelay:
// key for the relay map, and Core's relay signing key in mtsign: form, which
// the relay trusts.
type PublicKeys struct {
	Relay   string
	Signing string
}

// relayKeyText is a new relay key in the form "meshrelay genkey" writes.
func relayKeyText() ([]byte, error) {
	private, err := key.NewRelayPrivate()
	if err != nil {
		return nil, fmt.Errorf("%w: relay key: %w", ErrSecrets, err)
	}
	return []byte(private.PrivateText()), nil
}

// LoadPublicKeys derives the public keys from the generated relay key and
// relay signing seed (never through a link).
func LoadPublicKeys(dir string) (PublicKeys, error) {
	relayText, err := readRegularFile(filepath.Join(dir, "relay.key"), 256)
	if err != nil {
		return PublicKeys{}, fmt.Errorf("%w: read relay.key: %w", ErrSecrets, err)
	}
	defer clear(relayText)
	relay, err := key.ParseRelayPrivateBytes(relayText)
	if err != nil {
		return PublicKeys{}, fmt.Errorf("%w: relay.key does not parse", ErrSecrets)
	}
	seedText, err := readRegularFile(filepath.Join(dir, "relay-signing.key"), 256)
	if err != nil {
		return PublicKeys{}, fmt.Errorf("%w: read relay-signing.key: %w", ErrSecrets, err)
	}
	defer clear(seedText)
	seed, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimSpace(seedText)))
	if err != nil {
		return PublicKeys{}, fmt.Errorf("%w: relay-signing.key does not decode", ErrSecrets)
	}
	defer clear(seed)
	signing, err := key.SigningPrivateFromSeed(seed)
	if err != nil {
		return PublicKeys{}, fmt.Errorf("%w: relay-signing.key is not a seed", ErrSecrets)
	}
	return PublicKeys{Relay: relay.Public().String(), Signing: signing.Public().String()}, nil
}
