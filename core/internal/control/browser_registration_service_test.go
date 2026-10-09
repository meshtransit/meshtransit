package control

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

type browserIntentRepositoryFake struct {
	keys      *enrollment.BrowserIntentKeyring
	identity  node.RegistrationIdentity
	hostname  node.Hostname
	issued    int
	read      int
	state     enrollment.BrowserIntentFollowup
	found     bool
	issuedURL string
}

func (fake *browserIntentRepositoryFake) Issue(
	_ context.Context, deploymentID deployment.ID, epoch int64,
	identity node.RegistrationIdentity, hostname node.Hostname,
	intentID enrollment.BrowserIntentID, nonce enrollment.BrowserIntentNonce,
	_ time.Time,
) (enrollment.BrowserIntentToken, error) {
	fake.issued++
	fake.identity, fake.hostname = identity, hostname
	token, _, _, err := fake.keys.Issue(deploymentID, epoch, intentID, nonce)
	if err == nil {
		fake.issuedURL = token.Encoded()
		fake.state = enrollment.BrowserIntentFollowup{
			IntentID: intentID, State: "pending", ExpiresAt: time.Now().Add(5 * time.Minute),
		}
	}
	return token, err
}

func (fake *browserIntentRepositoryFake) ReadFollowup(
	_ context.Context, _ deployment.ID, _ int64,
	identity node.RegistrationIdentity, hostname node.Hostname, encoded string,
) (enrollment.BrowserIntentFollowup, bool, error) {
	fake.read++
	if identity != fake.identity || hostname != fake.hostname || encoded != fake.issuedURL {
		return enrollment.BrowserIntentFollowup{}, false, nil
	}
	return fake.state, fake.found, nil
}

func TestBrowserRegistrationServiceBindsIssueAndPoll(t *testing.T) {
	t.Parallel()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := enrollment.NewBrowserIntentKeyID("browser-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewBrowserIntentKey(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	fake := &browserIntentRepositoryFake{keys: keys, found: true}
	service, err := NewBrowserRegistrationService(fake, deploymentID, 1,
		"https://console.example.test", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey([32]byte{0: 2})
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.RegisterBrowser(t.Context(), machine, nodeKey, hostname, "")
	if err != nil || fake.issued != 1 || !strings.HasPrefix(issued,
		"https://console.example.test/register/v1/") {
		t.Fatalf("issue = (%q, %v), calls=%d", issued, err, fake.issued)
	}
	polled, err := service.RegisterBrowser(t.Context(), machine, nodeKey, hostname, issued)
	if err != nil || polled != issued || fake.read != 1 || fake.issued != 1 {
		t.Fatalf("poll = (%q, %v), read/issue=%d/%d", polled, err, fake.read, fake.issued)
	}
	for _, invalid := range []string{
		strings.Replace(issued, "console", "other", 1),
		issued + "?network=other",
		issued + "/extra",
	} {
		if _, err := service.RegisterBrowser(t.Context(), machine, nodeKey, hostname, invalid); !errors.Is(err, ErrInvalidBrowserRegistration) {
			t.Fatalf("accepted forged URL: %v", err)
		}
	}
	if fake.read != 1 {
		t.Fatalf("forged URL reached store: %d reads", fake.read)
	}
	otherNode, err := node.NewKey([32]byte{0: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterBrowser(t.Context(), machine, otherNode, hostname, issued); !errors.Is(err, ErrInvalidBrowserRegistration) {
		t.Fatalf("other Node polled intent: %v", err)
	}
	fake.found = false
	if _, err := service.RegisterBrowser(t.Context(), machine, nodeKey, hostname, issued); !errors.Is(err, ErrInvalidBrowserRegistration) {
		t.Fatalf("missing intent accepted: %v", err)
	}
}
