//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schema 291: the person's Device deviceID in Network 202 is held by the
// machine key of sibling, another profile on the same machine. A sign-in
// from a new profile (its own machine key) that proves sibling never makes
// a second Device of theirs in 202: the page names the Device, "Use that
// account" ends the sign-in with already_in_network, and a plain approval
// is refused at approval and again at completion.
func assertPostgreSQLBrowserSiblings(ctx context.Context, t *testing.T, admin *pgx.Conn,
	intents *postgresadapter.BrowserIntentStore, approval *postgresadapter.BrowserApprovalStore,
	completion *postgresadapter.BrowserCompletionStore, deploymentID deployment.ID, epoch int64,
	digest accountsession.Digest, sibling node.RegistrationIdentity, hostname node.Hostname,
	homeWorkspace workspace.ID, homeNetwork network.ID, deviceID string,
) {
	t.Helper()
	siblingKey := [32]byte(sibling.MachineKey().Bytes())
	profile := func(seed byte) node.RegistrationIdentity {
		t.Helper()
		machine, err := node.NewMachineKey([32]byte{0: 0xf0, 1: seed})
		if err != nil {
			t.Fatal(err)
		}
		nodeKey, err := node.NewKey([32]byte{0: 0xf1, 1: seed})
		if err != nil {
			t.Fatal(err)
		}
		identity, err := node.NewRegistrationIdentity(machine, nodeKey)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	issue := func(id string, identity node.RegistrationIdentity) string {
		t.Helper()
		intentID, err := enrollment.ParseBrowserIntentID(id)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := enrollment.NewBrowserIntentNonce()
		if err != nil {
			t.Fatal(err)
		}
		token, err := intents.Issue(ctx, deploymentID, epoch, identity, hostname, intentID, nonce, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return token.Encoded()
	}
	siblingRows := func(token string) int {
		t.Helper()
		intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(token)
		if err != nil {
			t.Fatal(err)
		}
		raw := intentDigest.Bytes()
		var rows int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.browser_intent_sibling sibling
JOIN mesh.browser_registration_intent intent ON intent.id=sibling.intent_id WHERE intent.token_digest=$1::BYTEA`,
			raw[:]).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}

	// The page names the Device, and a plain approval into its Network is
	// refused; another Network would still be approved.
	newProfile := profile(1)
	token := issue("01890f00-0000-7000-8000-000000002911", newProfile)
	stranger := [32]byte{0: 0xf2, 31: 1} // holds no Device
	if err := intents.RecordSiblings(ctx, deploymentID, epoch, newProfile, token,
		[][32]byte{siblingKey, stranger}); err != nil {
		t.Fatalf("record siblings: %v", err)
	}
	if err := intents.RecordSiblings(ctx, deploymentID, epoch, newProfile, token,
		[][32]byte{newProfile.MachineKey().Bytes()}); !errors.Is(err, postgresadapter.ErrInvalidBrowserSiblings) {
		t.Fatalf("recorded the sign-in's own key: %v", err)
	}
	devices, err := approval.LookupSiblingDevices(ctx, digest, token)
	if err != nil || len(devices) != 1 || devices[0].DeviceID != deviceID ||
		devices[0].NetworkID != homeNetwork.String() || devices[0].State != control.SiblingActive {
		t.Fatalf("page lookup = %+v/%v", devices, err)
	}
	if approved, err := approval.ApproveInWorkspace(ctx, digest, token, homeWorkspace, homeNetwork); err != nil || approved {
		t.Fatalf("plain approval into the sibling's Network = %v/%v", approved, err)
	}

	// "Use that account": the sign-in ends, makes no Device, and its
	// completion answers already_in_network with the sibling's key, again on
	// a replay.
	device, err := publicid.Parse(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := publicid.Parse("01890f00-0000-7000-8000-00000000d299")
	if err != nil {
		t.Fatal(err)
	}
	if joined, err := approval.JoinExistingDevice(ctx, digest, token, other); err != nil || joined {
		t.Fatalf("joined an unknown Device = %v/%v", joined, err)
	}
	var devicesBefore int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device`).Scan(&devicesBefore); err != nil {
		t.Fatal(err)
	}
	if joined, err := approval.JoinExistingDevice(ctx, digest, token, device); err != nil || !joined {
		t.Fatalf("use that account = %v/%v", joined, err)
	}
	if joined, err := approval.JoinExistingDevice(ctx, digest, token, device); err != nil || joined {
		t.Fatalf("joined twice = %v/%v", joined, err)
	}
	if rows := siblingRows(token); rows != 0 {
		t.Fatalf("a joined sign-in kept %d sibling keys", rows)
	}
	for attempt := range 2 {
		_, found, err := completion.CompleteWithSiblings(ctx, newProfile, hostname, token, nil)
		var joined *registration.JoinedExistingError
		if found || !errors.As(err, &joined) || joined.SiblingMachineKey != siblingKey {
			t.Fatalf("completion %d = %v/%v", attempt, found, err)
		}
	}
	var devicesAfter int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device`).Scan(&devicesAfter); err != nil ||
		devicesAfter != devicesBefore {
		t.Fatalf("joining made Devices: %d → %d (%v)", devicesBefore, devicesAfter, err)
	}

	// An approval made before any sibling was known is refused at
	// completion, by the keys the completing session proves (§19 N2).
	late := profile(2)
	lateToken := issue("01890f00-0000-7000-8000-000000002912", late)
	if approved, err := approval.ApproveInWorkspace(ctx, digest, lateToken, homeWorkspace, homeNetwork); err != nil || !approved {
		t.Fatalf("approval without siblings = %v/%v", approved, err)
	}
	if _, found, err := completion.CompleteWithSiblings(ctx, late, hostname, lateToken,
		[][32]byte{siblingKey}); found || !errors.Is(err, registration.ErrSiblingConflict) {
		t.Fatalf("completion with a proven sibling in that Network = %v/%v", found, err)
	}
}
