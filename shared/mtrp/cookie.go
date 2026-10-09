package mtrp

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"meshtransit.net/shared/key"
)

const (
	mac1Domain   = "meshtransit/mtrp-mac1/v1\x00"
	cookieDomain = "meshtransit/mtrp-cookie/v1\x00"
	// CookieSecretLifetime is how long a relay keeps one cookie secret.
	CookieSecretLifetime = 120 * time.Second
)

// ErrCookie reports a cookie reply that failed authentication.
var ErrCookie = errors.New("mtrp: invalid cookie reply")

// RelayMACKeys are the per-relay keys derived from its public key; both sides
// compute them once.
type RelayMACKeys struct {
	mac1   [blake2s.Size]byte
	cookie [blake2s.Size]byte
}

// NewRelayMACKeys derives mac1 and cookie keys for a relay.
func NewRelayMACKeys(relay key.RelayPublic) RelayMACKeys {
	var k RelayMACKeys
	k.mac1 = domainHash(mac1Domain, relay[:])
	k.cookie = domainHash(cookieDomain, relay[:])
	return k
}

func domainHash(domain string, data []byte) [blake2s.Size]byte {
	h, _ := blake2s.New256(nil) // unkeyed BLAKE2s never fails
	h.Write([]byte(domain))
	h.Write(data)
	var out [blake2s.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mac128(k, msg []byte) [MACSize]byte {
	h, err := blake2s.New128(k)
	if err != nil { // key length is fixed by construction; reaching this is a bug
		panic(fmt.Sprintf("mtrp: blake2s key: %v", err))
	}
	h.Write(msg)
	var out [MACSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MAC1 computes mac1 over a handshake frame's bytes before mac1.
func (k RelayMACKeys) MAC1(beforeMAC1 []byte) [MACSize]byte { return mac128(k.mac1[:], beforeMAC1) }

// CheckMAC1 verifies mac1 in constant time.
func (k RelayMACKeys) CheckMAC1(beforeMAC1 []byte, got [MACSize]byte) bool {
	want := k.MAC1(beforeMAC1)
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// MAC2 computes mac2 with a cookie over the bytes before mac2.
func MAC2(cookie [MACSize]byte, beforeMAC2 []byte) [MACSize]byte {
	return mac128(cookie[:], beforeMAC2)
}

// CheckMAC2 verifies mac2 in constant time.
func CheckMAC2(cookie [MACSize]byte, beforeMAC2 []byte, got [MACSize]byte) bool {
	want := MAC2(cookie, beforeMAC2)
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// SealCookie encrypts a cookie for the client that sent an INIT with mac1.
func (k RelayMACKeys) SealCookie(cookie, initMAC1 [MACSize]byte, random io.Reader) ([cookieNonceSize]byte, [encCookieSize]byte, error) {
	var nonce [cookieNonceSize]byte
	var sealed [encCookieSize]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nonce, sealed, fmt.Errorf("mtrp: cookie nonce: %w", err)
	}
	aead, err := chacha20poly1305.NewX(k.cookie[:])
	if err != nil {
		return nonce, sealed, fmt.Errorf("mtrp: cookie aead: %w", err)
	}
	copy(sealed[:], aead.Seal(nil, nonce[:], cookie[:], initMAC1[:]))
	return nonce, sealed, nil
}

// OpenCookie decrypts a cookie reply on the client.
func (k RelayMACKeys) OpenCookie(c Cookie, initMAC1 [MACSize]byte) ([MACSize]byte, error) {
	var cookie [MACSize]byte
	aead, err := chacha20poly1305.NewX(k.cookie[:])
	if err != nil {
		return cookie, fmt.Errorf("mtrp: cookie aead: %w", err)
	}
	plain, err := aead.Open(nil, c.Nonce[:], c.EncryptedCookie[:], initMAC1[:])
	if err != nil || len(plain) != MACSize {
		return cookie, ErrCookie
	}
	copy(cookie[:], plain)
	return cookie, nil
}

// CookieJar issues address-bound cookies from a secret rotated every
// CookieSecretLifetime. The zero value is not usable; use NewCookieJar. It is
// safe for concurrent use.
type CookieJar struct {
	random io.Reader
	now    func() time.Time

	mu      sync.Mutex
	secret  [blake2s.Size]byte
	created time.Time
}

// NewCookieJar returns a jar reading randomness from random (crypto/rand.Reader
// in production) and time from now (nil means time.Now).
func NewCookieJar(random io.Reader, now func() time.Time) (*CookieJar, error) {
	if random == nil {
		return nil, key.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	j := &CookieJar{random: random, now: now}
	if err := j.rotateLocked(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *CookieJar) rotateLocked() error {
	if _, err := io.ReadFull(j.random, j.secret[:]); err != nil {
		return fmt.Errorf("mtrp: cookie secret: %w", err)
	}
	j.created = j.now()
	return nil
}

// Cookie returns the cookie for a client address.
func (j *CookieJar) Cookie(addr netip.AddrPort) ([MACSize]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.now().Sub(j.created) >= CookieSecretLifetime {
		if err := j.rotateLocked(); err != nil {
			return [MACSize]byte{}, err
		}
	}
	ip := addr.Addr().As16()
	msg := make([]byte, 0, 18)
	msg = append(msg, ip[:]...)
	msg = binary.BigEndian.AppendUint16(msg, addr.Port())
	return mac128(j.secret[:], msg), nil
}
