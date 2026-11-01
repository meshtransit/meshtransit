package flowlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
)

const audience = "meshflow:01890f00-0000-7000-8000-000000000001"

var machineKey = bytes.Repeat([]byte{4}, 32)

func id(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func testClaims(now time.Time) *flowlogv1.FlowTokenClaims {
	return &flowlogv1.FlowTokenClaims{
		Version: 1, Kid: "flow-1", Audience: audience,
		WorkspaceId: id(1), NetworkId: id(2), DeviceId: id(3), MachineKey: bytes.Clone(machineKey),
		Roles:   []flowlogv1.FlowTokenClaims_Role{flowlogv1.FlowTokenClaims_DEVICE, flowlogv1.FlowTokenClaims_ROUTER},
		SiteIds: [][]byte{id(5)}, IssuedAtMs: now.UnixMilli(), NotBeforeMs: now.UnixMilli(),
		ExpiresAtMs: now.Add(15 * time.Minute).UnixMilli(), TokenId: id(6), WindowS: 60,
	}
}

func testKeys(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return private, map[string]ed25519.PublicKey{"flow-1": public}
}

// rawToken signs arbitrary claim bytes as Core would, for tokens SignToken
// refuses to make.
func rawToken(encoded []byte, key ed25519.PrivateKey) []byte {
	token := append([]byte(tokenMagic), 0, 0)
	binary.BigEndian.PutUint16(token[len(tokenMagic):], uint16(len(encoded))) //nolint:gosec // test sizes
	token = append(token, encoded...)
	return append(token, ed25519.Sign(key, signedBytes(encoded))...)
}

// verify runs both checks the receiver makes: the token before the body,
// then the machine key of the Noise message.
func verify(token []byte, keys map[string]ed25519.PublicKey, aud string, machine []byte, at time.Time) error {
	verified, err := VerifyToken(token, keys, aud, at)
	if err != nil {
		return err
	}
	_, err = verified.Claims(machine)
	return err
}

func TestTokenRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	private, keys := testKeys(t)
	token, err := SignToken(testClaims(now), private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyToken(token, keys, audience, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verified.Claims(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(claims.GetDeviceId(), id(3)) || len(claims.GetRoles()) != 2 {
		t.Fatalf("claims %+v", claims)
	}
	// The claims handed out are a copy: changing them changes no later answer.
	claims.DeviceId = id(9)
	again, err := verified.Claims(machineKey)
	if err != nil || !bytes.Equal(again.GetDeviceId(), id(3)) {
		t.Fatalf("claims changed under the token: %v", err)
	}
	var none *Token
	if _, err := none.Claims(machineKey); !errors.Is(err, ErrWrongMachineKey) {
		t.Fatalf("a nil token: %v", err)
	}
}

// A token is refused when tampered with, signed by another key, meant for
// another receiver, presented under another machine key, or outside its
// window beyond the clock skew.
func TestTokenRefusals(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	private, keys := testKeys(t)
	token, err := SignToken(testClaims(now), private)
	if err != nil {
		t.Fatal(err)
	}
	otherPrivate, _ := testKeys(t)
	forged, err := SignToken(testClaims(now), otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(token)
	flipped[len(tokenMagic)+4] ^= 1
	unknownKID := testClaims(now)
	unknownKID.Kid = "flow-2"
	unknown, err := SignToken(unknownKID, private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(testClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	// A field this reader does not know, correctly signed.
	extra := protowire.AppendTag(bytes.Clone(encoded), 99, protowire.VarintType)
	extra = protowire.AppendVarint(extra, 1)
	longer, shorter := bytes.Clone(token), bytes.Clone(token)
	binary.BigEndian.PutUint16(longer[len(tokenMagic):], uint16(len(encoded)+1))  //nolint:gosec // test sizes
	binary.BigEndian.PutUint16(shorter[len(tokenMagic):], uint16(len(encoded)-1)) //nolint:gosec // test sizes
	for name, test := range map[string]struct {
		token   []byte
		at      time.Time
		aud     string
		machine []byte
		want    error
	}{
		"tampered":         {flipped, now, audience, machineKey, ErrInvalidToken},
		"another key":      {forged, now, audience, machineKey, ErrInvalidToken},
		"unknown kid":      {unknown, now, audience, machineKey, ErrUnknownKey},
		"another receiver": {token, now, "meshflow:other", machineKey, ErrInvalidToken},
		"another machine":  {token, now, audience, bytes.Repeat([]byte{5}, 32), ErrWrongMachineKey},
		"no machine key":   {token, now, audience, nil, ErrWrongMachineKey},
		"unknown field":    {rawToken(extra, private), now, audience, machineKey, ErrInvalidToken},
		"trailing bytes":   {append(bytes.Clone(token), 0), now, audience, machineKey, ErrInvalidToken},
		"truncated":        {token[:len(token)-1], now, audience, machineKey, ErrInvalidToken},
		"length too long":  {longer, now, audience, machineKey, ErrInvalidToken},
		"length too short": {shorter, now, audience, machineKey, ErrInvalidToken},
		"wrong magic":      {append([]byte("MFT2"), token[4:]...), now, audience, machineKey, ErrInvalidToken},
		"too large":        {make([]byte, MaxTokenSize+1), now, audience, machineKey, ErrInvalidToken},
		"expired":          {token, now.Add(15*time.Minute + ClockSkew), audience, machineKey, ErrTokenExpired},
		"not yet valid":    {token, now.Add(-ClockSkew - time.Millisecond), audience, machineKey, ErrTokenExpired},
	} {
		if err := verify(test.token, keys, test.aud, test.machine, test.at); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
	// The edges of the skew: valid from not_before − skew, until expiry + skew.
	for _, at := range []time.Time{now.Add(-ClockSkew), now.Add(15*time.Minute + ClockSkew - time.Millisecond)} {
		if err := verify(token, keys, audience, machineKey, at); err != nil {
			t.Errorf("at %v: %v", at.Sub(now), err)
		}
	}
	short := map[string]ed25519.PublicKey{"flow-1": ed25519.PublicKey(make([]byte, 31))}
	if err := verify(token, short, audience, machineKey, now); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("a wrong-size public key: %v", err)
	}
}

// Core never signs claims outside the bounds of flowlog-v1 §3.
func TestSignTokenRefusesBadClaims(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	private, _ := testKeys(t)
	for name, change := range map[string]func(*flowlogv1.FlowTokenClaims){
		"no roles":          func(c *flowlogv1.FlowTokenClaims) { c.Roles = nil },
		"unknown role":      func(c *flowlogv1.FlowTokenClaims) { c.Roles = []flowlogv1.FlowTokenClaims_Role{9} },
		"duplicate role":    func(c *flowlogv1.FlowTokenClaims) { c.Roles = append(c.Roles, flowlogv1.FlowTokenClaims_DEVICE) },
		"router no sites":   func(c *flowlogv1.FlowTokenClaims) { c.SiteIds = nil },
		"pools no exit":     func(c *flowlogv1.FlowTokenClaims) { c.ExitPoolIds = [][]byte{id(7)} },
		"duplicate site":    func(c *flowlogv1.FlowTokenClaims) { c.SiteIds = [][]byte{id(5), id(5)} },
		"too long":          func(c *flowlogv1.FlowTokenClaims) { c.ExpiresAtMs = now.Add(16 * time.Minute).UnixMilli() },
		"short device id":   func(c *flowlogv1.FlowTokenClaims) { c.DeviceId = c.DeviceId[:15] },
		"short machine key": func(c *flowlogv1.FlowTokenClaims) { c.MachineKey = c.MachineKey[:31] },
		"no audience":       func(c *flowlogv1.FlowTokenClaims) { c.Audience = "" },
		"long audience":     func(c *flowlogv1.FlowTokenClaims) { c.Audience = string(bytes.Repeat([]byte{'a'}, 81)) },
		"window too small":  func(c *flowlogv1.FlowTokenClaims) { c.WindowS = 30 },
		"bad site id":       func(c *flowlogv1.FlowTokenClaims) { c.SiteIds = [][]byte{{1}} },
		"version 2":         func(c *flowlogv1.FlowTokenClaims) { c.Version = 2 },
		"expires first":     func(c *flowlogv1.FlowTokenClaims) { c.ExpiresAtMs = c.NotBeforeMs },
		"long kid":          func(c *flowlogv1.FlowTokenClaims) { c.Kid = string(bytes.Repeat([]byte{'k'}, 33)) },
		"kid charset":       func(c *flowlogv1.FlowTokenClaims) { c.Kid = "flow 1" },
	} {
		claims := testClaims(now)
		change(claims)
		if _, err := SignToken(claims, private); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := SignToken(nil, private); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("nil claims: %v", err)
	}
	if _, err := SignToken(testClaims(now), private[:10]); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("short private key: %v", err)
	}
}

// The largest claims Core may sign still fit MaxTokenSize, so a router or
// gateway with many scopes is never left without logging.
func TestLargestClaimsFit(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	private, keys := testKeys(t)
	claims := testClaims(now)
	claims.Kid = string(bytes.Repeat([]byte{'k'}, maxKIDLength))
	claims.Audience = "meshflow:" + string(bytes.Repeat([]byte{'d'}, MaxAudienceLength-len("meshflow:")))
	claims.Roles = []flowlogv1.FlowTokenClaims_Role{
		flowlogv1.FlowTokenClaims_DEVICE, flowlogv1.FlowTokenClaims_ROUTER,
		flowlogv1.FlowTokenClaims_EXIT, flowlogv1.FlowTokenClaims_GATEWAY,
	}
	claims.SiteIds, claims.ExitPoolIds, claims.ClusterIds = nil, nil, nil
	for index := range MaxScopeIDs {
		scoped := bytes.Repeat([]byte{byte(index)}, 16)
		switch index % 3 {
		case 0:
			claims.SiteIds = append(claims.SiteIds, scoped)
		case 1:
			claims.ExitPoolIds = append(claims.ExitPoolIds, scoped)
		default:
			claims.ClusterIds = append(claims.ClusterIds, scoped)
		}
	}
	claims.WindowS = 300
	token, err := SignToken(claims, private)
	if err != nil {
		t.Fatalf("the largest claims: %v", err)
	}
	if len(token) > MaxTokenSize-64 {
		t.Errorf("the largest token is %d bytes, leaving under 64 bytes of %d", len(token), MaxTokenSize)
	}
	keys = map[string]ed25519.PublicKey{claims.Kid: keys["flow-1"]}
	if err := verify(token, keys, claims.Audience, machineKey, now); err != nil {
		t.Fatal(err)
	}
	claims.ClusterIds = append(claims.ClusterIds, id(9))
	if _, err := SignToken(claims, private); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("one ID past the cap: %v", err)
	}
}

func TestReadClaims(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	private, _ := testKeys(t)
	token, err := SignToken(testClaims(now), private)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ReadClaims(token)
	if err != nil || claims.GetWindowS() != 60 || !bytes.Equal(claims.GetNetworkId(), id(2)) {
		t.Fatalf("claims %v %v", claims, err)
	}
	for _, bad := range [][]byte{nil, token[:len(token)-1], append(bytes.Clone(token), 0), []byte("MFT2")} {
		if _, err := ReadClaims(bad); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("ReadClaims(%d bytes) = %v", len(bad), err)
		}
	}
}

type shortSigner struct{}

func (shortSigner) Sign([]byte) []byte { return []byte{1} }

// A signer that hides its key signs the same token, and a key's kid is
// fixed by its public half.
func TestSignTokenWith(t *testing.T) {
	t.Parallel()
	key, keys := testKeys(t)
	now := time.Now()
	direct, err := SignToken(testClaims(now), key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := SignTokenWith(testClaims(now), ed25519Signer(key))
	if err != nil || !bytes.Equal(direct, wrapped) {
		t.Fatalf("SignTokenWith() = %v", err)
	}
	if err := verify(wrapped, keys, audience, machineKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := SignTokenWith(testClaims(now), shortSigner{}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a short signature: %v", err)
	}
	if _, err := SignTokenWith(testClaims(now), nil); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("no signer: %v", err)
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key")
	}
	kid := SigningKeyID(public)
	if !validKID(kid) || kid != SigningKeyID(bytes.Clone(public)) || len(kid) != 20 {
		t.Errorf("kid %q", kid)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if SigningKeyID(other) == kid {
		t.Error("two keys share a kid")
	}
}
