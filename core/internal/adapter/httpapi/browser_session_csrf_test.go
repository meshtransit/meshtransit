package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

func browserProofFixture(
	t *testing.T,
	browser *BrowserManagement,
	now time.Time,
) (accountsession.Token, browserSessionProof) {
	t.Helper()
	token, err := accountsession.ParseToken(managementTokenFixture)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := browser.sealProof(
		token,
		managementSessionFixture(t),
		now,
		[32]byte{31: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	return token, proof
}

func TestBrowserSessionProofHasExactPurposeScopeAndExclusiveTime(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	token, proof := browserProofFixture(t, browser, fixture.at)
	if strings.Contains(proof.encoded, token.Encoded()) || len(proof.encoded) > maximumBrowserSessionProofBytes {
		t.Fatal("proof exposes bearer or exceeds bound")
	}
	for index := range proof.encoded {
		tampered := []byte(proof.encoded)
		tampered[index] ^= 1
		if _, err := browser.readProof(token, string(tampered), fixture.at); err == nil {
			t.Fatal("proof accepted byte tampering", index)
		}
	}
	for _, at := range []time.Time{
		proof.issued.Add(-time.Nanosecond), proof.expires, proof.expires.Add(time.Nanosecond), {},
	} {
		if _, err := browser.readProof(token, proof.encoded, at); err == nil {
			t.Fatal("proof accepted future issue, exclusive expiry or invalid clock")
		}
	}
	if _, err := browser.readProof(token, proof.encoded, proof.expires.Add(-time.Nanosecond)); err != nil {
		t.Fatal("last valid proof instant failed", err)
	}
	for _, mode := range []string{"origin", "key", "key id", "cookie", "recovery", "purpose"} {
		t.Run(mode, func(t *testing.T) {
			other, _ := newBrowserManagementFixture(t)
			candidate, encoded := token, proof.encoded
			switch mode {
			case "origin":
				other.origin = "https://other.example.test"
			case "key":
				other.key[0] ^= 1
			case "key id":
				other.keyID = "other"
			case "cookie":
				candidate, _ = accountsession.ParseToken(strings.Replace(
					managementTokenFixture,
					"AQE",
					"AgI",
					1,
				))
			case "recovery":
				candidate, _ = accountsession.ParseToken(strings.Replace(
					managementTokenFixture,
					".7.",
					".8.",
					1,
				))
			case "purpose":
				encoded = strings.Replace(
					encoded,
					"mtscsrf1",
					"mtlc1",
					1,
				)
			}
			if _, err := other.readProof(candidate, encoded, fixture.at); err == nil {
				t.Fatal("proof accepted different scope/purpose/bearer")
			}
		})
	}
	if _, err := json.Marshal(proof); err == nil || strings.Contains(fmt.Sprintf("%v %#v", proof, proof), proof.encoded) {
		t.Fatal("proof leaked through generic encoding/formatting")
	}
}

func TestBrowserSessionProofShortensToDurableSessionExpiry(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	token, _ := accountsession.ParseToken(managementTokenFixture)
	base := managementSessionFixture(t)
	workspaceID, hasWorkspace := base.LoginWorkspaceID()
	expiry := fixture.at.Add(35*time.Second + 500*time.Millisecond)
	session, err := accountsession.NewSession(accountsession.Params{ID: base.ID(), DeploymentID: base.DeploymentID(),
		PrincipalID: base.PrincipalID(), IdentitySubjectID: base.IdentitySubjectID(), LoginWorkspaceID: workspaceID,
		HasLoginWorkspace: hasWorkspace, AuthenticationTime: base.AuthenticationTime(), ACR: base.ACR(), AMR: base.AMR(),
		Version: base.Version(), PrincipalAuthorityGeneration: base.PrincipalAuthorityGeneration(),
		AccountSessionGeneration: base.AccountSessionGeneration(), ProviderGeneration: base.ProviderGeneration(),
		DeploymentRecoveryEpoch: base.DeploymentRecoveryEpoch(), IdleExpiresAt: expiry, AbsoluteExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := browser.sealProof(
		token,
		session,
		fixture.at,
		[32]byte{0: 1},
	)
	if err != nil || !proof.expires.Equal(expiry.Truncate(time.Second)) {
		t.Fatal("proof was not shortened/floored to Session authority", err)
	}
	_, nearExpiryErr := browser.sealProof(
		token,
		session,
		expiry.Add(-time.Second),
		[32]byte{0: 1},
	)
	if nearExpiryErr == nil {
		t.Fatal("sub-second proof issued near Session expiry")
	}
}

func FuzzBrowserSessionProof(f *testing.F) {
	token, err := accountsession.ParseToken(managementTokenFixture)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(
		2026,
		time.September,
		16,
		0,
		0,
		0,
		0,
		time.UTC,
	)
	browser := &BrowserManagement{
		deploymentID: token.DeploymentID(), origin: "https://console.example.test",
		keyID: "browser-session-csrf-v1", lifetime: time.Minute,
	}
	for index := range browser.key {
		browser.key[index] = 0x54
	}
	nonce := [32]byte{31: 1}
	payload := strings.Join([]string{
		"mtscsrf1", browser.keyID, strconv.FormatInt(now.Unix(), 10),
		strconv.FormatInt(now.Add(time.Minute).Unix(), 10), base64.RawURLEncoding.EncodeToString(nonce[:]),
	}, ".")
	mac, err := browser.proofMAC(token, payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload + "." + base64.RawURLEncoding.EncodeToString(mac))
	f.Add("")
	f.Add(strings.Repeat(".", 300))
	f.Fuzz(func(t *testing.T, encoded string) {
		actual, err := browser.readProof(token, encoded, now)
		invalidEncoding := len(encoded) > maximumBrowserSessionProofBytes || actual.encoded != encoded
		invalidWindow := !now.Before(actual.expires) || now.Before(actual.issued)
		if err == nil && (invalidEncoding || invalidWindow) {
			t.Fatal("unverified/unbounded proof accepted")
		}
	})
}
