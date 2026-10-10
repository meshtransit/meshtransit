package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/peerprobe"
	"meshtransit.net/shared/disco"

	"meshtransit.net/shared/key"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/secretstore"
	"meshtransit.net/client/internal/version"
)

func TestService_TrustAndBrowserRegistration(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlTrust != ControlTrustUnconfigured || status.Registration != RegistrationUnregistered {
		t.Fatalf("initial status = %#v, want unconfigured/unregistered", status)
	}

	trusted, err := service.TrustControl(t.Context(), testFingerprint)
	if err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	if trusted.ProfileID != profileID || trusted.AlreadyTrusted {
		t.Fatalf("TrustControl() = %#v, want newly trusted profile", trusted)
	}
	trustedAgain, err := service.TrustControl(t.Context(), strings.ToUpper(testFingerprint))
	if err != nil {
		t.Fatalf("second TrustControl() error = %v", err)
	}
	if !trustedAgain.AlreadyTrusted || control.bootstrapCalls != 1 || control.verifyCalls != 1 {
		t.Fatalf("repeat trust = %#v, calls bootstrap=%d verify=%d", trustedAgain, control.bootstrapCalls, control.verifyCalls)
	}

	control.registrationResults = []controlplane.RegistrationResult{
		{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
		{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		},
	}
	login, err := service.StartLogin(t.Context(), "")
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if login.State != RegistrationPending || login.AuthURL == "" {
		t.Fatalf("StartLogin() = %#v, want browser authorization", login)
	}
	completed, err := service.CompleteLogin(t.Context())
	if err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	if completed.State != RegistrationRegistered || completed.AuthURL != "" {
		t.Fatalf("CompleteLogin() = %#v, want registered", completed)
	}

	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	if !record.IsRegistered() || record.HasPendingAuth() {
		t.Fatalf("persisted registration = %s, want registered", record)
	}
}

// Explicit login must ask the pinned control plane for its current intent, even
// after a pending URL was persisted. The server decides whether to replay a
// live intent or replace an expired one; the client does not guess its expiry.
func TestService_StartLoginRechecksPendingAuthorization(t *testing.T) {
	t.Parallel()

	const oldURL = "https://control.example.com/register/old"
	const newURL = "https://control.example.com/register/new"
	for _, test := range []struct {
		name   string
		result controlplane.RegistrationResult
		state  string
		url    string
	}{
		{
			name: "live intent replay",
			result: controlplane.RegistrationResult{
				State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: oldURL,
			},
			state: RegistrationPending, url: oldURL,
		},
		{
			name: "expired intent replacement",
			result: controlplane.RegistrationResult{
				State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: newURL,
			},
			state: RegistrationPending, url: newURL,
		},
		{
			name: "already authorized",
			result: controlplane.RegistrationResult{
				State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true,
			},
			state: RegistrationRegistered,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, identities, control, profileID, _ := newTestService(t)
			if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
				t.Fatal(err)
			}
			control.registrationResults = []controlplane.RegistrationResult{
				{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: oldURL},
				test.result,
			}
			if _, err := service.StartLogin(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			before, err := identities.Get(t.Context(), profileID)
			if err != nil {
				t.Fatal(err)
			}
			beforeMaterial := before.Material()
			defer clearIdentityMaterial(beforeMaterial)
			login, err := service.StartLogin(t.Context(), "")
			if err != nil || login.State != test.state || login.AuthURL != test.url {
				t.Fatalf("explicit login = %s, URL matches = %t, error = %v", login.State, login.AuthURL == test.url, err)
			}
			control.mu.Lock()
			options := slices.Clone(control.registerOptions)
			control.mu.Unlock()
			if len(options) != 2 || options[1].AuthKey != "" || options[1].FollowupURL != "" ||
				options[1].PinnedFingerprint != testFingerprint {
				t.Fatal("explicit login did not recheck the current intent using pinned identity and no scope selector")
			}
			after, err := identities.Get(t.Context(), profileID)
			if err != nil {
				t.Fatal(err)
			}
			afterMaterial := after.Material()
			defer clearIdentityMaterial(afterMaterial)
			if !bytes.Equal(beforeMaterial.MachinePrivateKey, afterMaterial.MachinePrivateKey) ||
				!bytes.Equal(beforeMaterial.NodePrivateKey, afterMaterial.NodePrivateKey) ||
				!bytes.Equal(beforeMaterial.ControlPublicKey, afterMaterial.ControlPublicKey) ||
				after.ControlKeyFingerprint() != before.ControlKeyFingerprint() {
				t.Fatal("explicit login changed identity or trust")
			}
			if after.PendingAuthURL() != test.url || after.IsRegistered() != (test.state == RegistrationRegistered) {
				t.Fatal("server-confirmed login state was not persisted")
			}
		})
	}
}

func TestService_StartLoginPreservesPendingAuthorizationOnFailure(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "temporary failure", err: controlplane.ErrRegistrationTemporary},
		{name: "control key changed", err: controlplane.ErrControlKeyChanged},
		{name: "rejected response", err: controlplane.ErrRegistration},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, identities, control, profileID, _ := newTestService(t)
			if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
				t.Fatal(err)
			}
			const pendingURL = "https://control.example.com/register/old"
			control.registrationResults = []controlplane.RegistrationResult{
				{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: pendingURL},
			}
			if _, err := service.StartLogin(t.Context(), ""); err != nil {
				t.Fatal(err)
			}
			control.registerFunc = func(context.Context, controlplane.RegisterOptions) (controlplane.RegistrationResult, error) {
				return controlplane.RegistrationResult{}, test.err
			}
			if _, err := service.StartLogin(t.Context(), ""); !errors.Is(err, test.err) {
				t.Fatalf("explicit login error = %v, want %v", err, test.err)
			}
			record, err := identities.Get(t.Context(), profileID)
			if err != nil {
				t.Fatal(err)
			}
			if record.PendingAuthURL() != pendingURL || record.IsRegistered() {
				t.Fatal("failed recheck discarded or authorized pending state")
			}
		})
	}
}

func TestService_RotateNodeKeyCommitsConfirmedKey(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() before rotation error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)
	oldNodePrivateKey := bytes.Clone(oldMaterial.NodePrivateKey)
	defer clear(oldNodePrivateKey)

	control.rotationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	rotated, err := service.RotateNodeKey(t.Context())
	if err != nil {
		t.Fatalf("RotateNodeKey() error = %v", err)
	}
	if rotated.ProfileID != profileID || rotated.State != nodeKeyRotationCompleted {
		t.Fatalf("RotateNodeKey() = %#v, want committed rotation", rotated)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() after rotation error = %v", err)
	}
	if after.HasPendingNodeKeyRotation() {
		t.Fatal("confirmed rotation retained pending key")
	}
	newMaterial := after.Material()
	defer clearIdentityMaterial(newMaterial)
	if bytes.Equal(newMaterial.NodePrivateKey, oldNodePrivateKey) {
		t.Fatal("confirmed rotation did not replace active Node private key")
	}

	control.mu.Lock()
	rotationKeys := cloneByteSlices(control.rotationKeys)
	rotationMaterials := cloneProtocolMaterials(control.rotationMaterials)
	control.mu.Unlock()
	defer clearByteSlices(rotationKeys)
	defer clearProtocolMaterials(rotationMaterials)
	if len(rotationKeys) != 1 || len(rotationMaterials) != 1 {
		t.Fatalf("rotation calls = %d/%d, want 1/1", len(rotationKeys), len(rotationMaterials))
	}
	if !bytes.Equal(rotationMaterials[0].NodePrivateKey, oldNodePrivateKey) {
		t.Fatal("rotation request was not authenticated with active old Node key")
	}
	if !bytes.Equal(rotationKeys[0], newMaterial.NodePrivateKey) {
		t.Fatal("persisted Node key differs from the key confirmed by control")
	}
}

func TestService_RotateNodeKeyRetriesSameStagedKey(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() before rotation error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)

	rotationCall := 0
	control.rotateFunc = func(
		_ context.Context,
		_ []byte,
	) (controlplane.RegistrationResult, error) {
		rotationCall++
		if rotationCall == 1 {
			return controlplane.RegistrationResult{}, fmt.Errorf(
				"%w: injected transport failure",
				controlplane.ErrRegistrationTemporary,
			)
		}

		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}
	if _, err := service.RotateNodeKey(t.Context()); !errors.Is(err, controlplane.ErrRegistrationTemporary) ||
		!errors.Is(err, ErrNodeKeyRotation) {
		t.Fatalf("first RotateNodeKey() error = %v, want temporary rotation error", err)
	}
	pendingRecord, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() pending rotation error = %v", err)
	}
	pendingNodePrivateKey := pendingRecord.PendingNodePrivateKey()
	defer clear(pendingNodePrivateKey)
	if len(pendingNodePrivateKey) == 0 {
		t.Fatal("temporary failure did not retain staged Node key")
	}
	pendingMaterial := pendingRecord.Material()
	defer clearIdentityMaterial(pendingMaterial)
	if !bytes.Equal(pendingMaterial.NodePrivateKey, oldMaterial.NodePrivateKey) {
		t.Fatal("temporary failure changed active Node key")
	}

	if _, err := service.RotateNodeKey(t.Context()); err != nil {
		t.Fatalf("second RotateNodeKey() error = %v", err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() after retry error = %v", err)
	}
	afterMaterial := after.Material()
	defer clearIdentityMaterial(afterMaterial)
	if after.HasPendingNodeKeyRotation() ||
		!bytes.Equal(afterMaterial.NodePrivateKey, pendingNodePrivateKey) {
		t.Fatalf("retry did not promote exact staged key: %s", after)
	}

	control.mu.Lock()
	rotationKeys := cloneByteSlices(control.rotationKeys)
	control.mu.Unlock()
	defer clearByteSlices(rotationKeys)
	if len(rotationKeys) != 2 ||
		!bytes.Equal(rotationKeys[0], pendingNodePrivateKey) ||
		!bytes.Equal(rotationKeys[1], pendingNodePrivateKey) {
		t.Fatal("rotation retry did not reuse the exact staged Node key")
	}
}

func TestService_RunResumesPendingNodeKeyRotation(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	pendingNodePrivateKey, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		t.Fatalf("GenerateNodePrivateKey() error = %v", err)
	}
	defer clear(pendingNodePrivateKey)
	if _, err := identities.BeginNodeKeyRotation(
		t.Context(),
		profileID,
		pendingNodePrivateKey,
	); err != nil {
		t.Fatalf("BeginNodeKeyRotation() error = %v", err)
	}
	control.rotationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	waitForStreamStart(t, control)
	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() after resume error = %v", err)
	}
	afterMaterial := after.Material()
	defer clearIdentityMaterial(afterMaterial)
	if after.HasPendingNodeKeyRotation() ||
		!bytes.Equal(afterMaterial.NodePrivateKey, pendingNodePrivateKey) {
		t.Fatalf("Run() did not promote the staged Node key: %s", after)
	}
	control.mu.Lock()
	rotationKeys := cloneByteSlices(control.rotationKeys)
	control.mu.Unlock()
	defer clearByteSlices(rotationKeys)
	if len(rotationKeys) != 1 || !bytes.Equal(rotationKeys[0], pendingNodePrivateKey) {
		t.Fatal("Run() did not resume the exact pending Node-key transition")
	}
}

func TestService_CompleteLoginSerializesPendingAuthorization(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:   controlplane.RegistrationStateAuthorizationRequired,
		AuthURL: "https://control.example.com/register/opaque",
	}}
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	registerStarted := make(chan struct{}, 2)
	releaseRegister := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRegister) }) }
	defer release()
	control.mu.Lock()
	control.registerFunc = func(
		ctx context.Context,
		_ controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error) {
		registerStarted <- struct{}{}
		select {
		case <-ctx.Done():
			return controlplane.RegistrationResult{}, ctx.Err()
		case <-releaseRegister:
			return controlplane.RegistrationResult{
				State:             controlplane.RegistrationStateAuthorized,
				MachineAuthorized: true,
			}, nil
		}
	}
	control.mu.Unlock()

	firstDone := make(chan error, 1)
	go func() {
		_, err := service.CompleteLogin(t.Context())
		firstDone <- err
	}()
	select {
	case <-registerStarted:
	case <-time.After(time.Second):
		t.Fatal("first login completion did not reach the control adapter")
	}

	secondCtx, cancelSecond := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelSecond()
	secondDone := make(chan error, 1)
	go func() {
		_, err := service.CompleteLogin(secondCtx)
		secondDone <- err
	}()

	select {
	case <-registerStarted:
		t.Error("second login completion reached the control adapter concurrently")
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("second CompleteLogin() error = %v, want context deadline", err)
		}
	case <-time.After(time.Second):
		t.Error("second login completion did not honor context cancellation")
	}

	release()
	if err := <-firstDone; err != nil {
		t.Fatalf("first CompleteLogin() error = %v", err)
	}
	if _, err := service.CompleteLogin(t.Context()); !errors.Is(err, ErrNoPendingAuthorization) {
		t.Fatalf("completed flow error = %v, want ErrNoPendingAuthorization", err)
	}
	control.mu.Lock()
	registerCalls := len(control.registerOptions)
	control.mu.Unlock()
	if registerCalls != 2 {
		t.Fatalf("control registration calls = %d, want start plus one completion", registerCalls)
	}
}

func TestService_CompleteLoginKeepsPendingStateOnTemporaryFailure(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:   controlplane.RegistrationStateAuthorizationRequired,
		AuthURL: "https://control.example.com/register/opaque",
	}}
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	const pollTimeout = 25 * time.Millisecond
	control.mu.Lock()
	control.registerFunc = func(
		context.Context,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error) {
		return controlplane.RegistrationResult{}, fmt.Errorf(
			"test control outage: %w",
			controlplane.ErrRegistrationTemporary,
		)
	}
	control.mu.Unlock()
	startedAt := time.Now()
	if _, err := service.completeLogin(t.Context(), pollTimeout); !errors.Is(err, ErrAuthorizationPending) ||
		!errors.Is(err, controlplane.ErrRegistrationTemporary) {
		t.Fatalf("CompleteLogin() error = %v, want pending temporary failure", err)
	}
	if elapsed := time.Since(startedAt); elapsed < pollTimeout {
		t.Fatalf("temporary failure returned after %s, want at least %s", elapsed, pollTimeout)
	}
	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	if !record.HasPendingAuth() || record.IsRegistered() {
		t.Fatalf("registration after temporary failure = %s, want pending", record)
	}

	control.mu.Lock()
	control.registerFunc = func(
		context.Context,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error) {
		return controlplane.RegistrationResult{
			State:             controlplane.RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}
	control.mu.Unlock()
	login, err := service.CompleteLogin(t.Context())
	if err != nil || login.State != RegistrationRegistered {
		t.Fatalf("recovered CompleteLogin() = %#v, %v", login, err)
	}
}

func TestService_CompleteLoginThrottlesPendingResponse(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{
		{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
		{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
	}

	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	const pollTimeout = 25 * time.Millisecond
	startedAt := time.Now()
	login, err := service.completeLogin(t.Context(), pollTimeout)
	if err != nil || login.State != RegistrationPending {
		t.Fatalf("completeLogin() = %#v, %v, want pending", login, err)
	}
	if elapsed := time.Since(startedAt); elapsed < pollTimeout {
		t.Fatalf("pending response returned after %s, want at least %s", elapsed, pollTimeout)
	}
	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	if !record.HasPendingAuth() || record.IsRegistered() {
		t.Fatalf("registration after pending response = %s, want pending", record)
	}
}

func TestService_CompleteLoginPersistsResponseAfterPollDeadline(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{
		{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
		{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
	}
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	login, err := service.completeLogin(t.Context(), time.Nanosecond)
	if err != nil || login.ProfileID != profileID ||
		login.State != RegistrationPending || login.AuthURL == "" {
		t.Fatalf("completeLogin() = %#v, %v, want persisted pending response", login, err)
	}
	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	if !record.HasPendingAuth() || record.PendingAuthURL() != login.AuthURL {
		t.Fatalf("registration after expired poll deadline = %s", record)
	}
}

func TestService_RegistrationClearsTemporaryKeyMaterial(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	control.mu.Lock()
	material := control.registerMaterial
	control.mu.Unlock()
	for name, secret := range map[string][]byte{
		"machine": material.MachinePrivateKey,
		"node":    material.NodePrivateKey,
		"control": material.ControlPublicKey,
	} {
		if len(secret) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("temporary %s key material was not cleared", name)
		}
	}
}

func TestService_CompleteLoginTemporaryFailureHonorsCancellation(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:   controlplane.RegistrationStateAuthorizationRequired,
		AuthURL: "https://control.example.com/register/opaque",
	}}
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	registerStarted := make(chan struct{}, 1)
	control.mu.Lock()
	control.registerFunc = func(
		context.Context,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error) {
		registerStarted <- struct{}{}

		return controlplane.RegistrationResult{}, fmt.Errorf(
			"test control outage: %w",
			controlplane.ErrRegistrationTemporary,
		)
	}
	control.mu.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := service.completeLogin(ctx, time.Hour)
		done <- err
	}()
	select {
	case <-registerStarted:
	case <-time.After(time.Second):
		t.Fatal("login completion did not reach the control adapter")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CompleteLogin() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CompleteLogin() did not stop after cancellation")
	}
}

func TestService_AuthKeyIsNotPersisted(t *testing.T) {
	t.Parallel()

	service, _, control, profileID, stateDir := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	const authKey = "sensitive-auth-key-value"
	if _, err := service.StartLogin(t.Context(), authKey); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if got := control.registerOptions[0].AuthKey; got != authKey {
		t.Fatalf("adapter auth key = %q, want in-memory value", got)
	}

	//nolint:gosec // The test reads a file under its own temporary directory.
	encoded, err := os.ReadFile(filepath.Join(stateDir, "identities", profileID+".json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(encoded), authKey) {
		t.Fatal("persisted identity contains auth key")
	}
}

func TestService_LoginRequiresTrust(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	if _, err := service.StartLogin(t.Context(), ""); !errors.Is(err, ErrControlNotTrusted) {
		t.Fatalf("StartLogin() error = %v, want ErrControlNotTrusted", err)
	}
}

func TestService_PathProbeStatusIsRedactedAndProcessLocal(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	service.dataPlane = newFakeLiveProbeDataPlane()
	service.pathProbes.RecordMapActivation()
	service.pathProbes.RecordProbeSent()
	service.pathProbes.RecordCompletionRejection()
	service.pathProbes.RecordDirectExpiry(2)

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.PathProbes.Available {
		t.Fatal("PathProbes.Available = false, want true")
	}
	want := pathdiscovery.ProbeTelemetrySnapshot{
		MapActivations:       1,
		ProbesSent:           1,
		CompletionRejections: 1,
		DirectExpirations:    2,
	}
	if status.PathProbes.Snapshot != want {
		t.Fatalf("PathProbes.Snapshot = %#v, want %#v", status.PathProbes.Snapshot, want)
	}
}

func TestService_RunPublishesLatestValidatedSnapshot(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	dataPlane := &fakeDataPlane{}
	dns := &fakeDNS{configured: true}
	service.dataPlane = dataPlane
	service.enableDeviceAliases = true
	service.dns = dns
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision:    7,
		NetworkName: "network.example.mesh",
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers:  make([]networkmap.Node, 2),
		Policy: make([]networkmap.Rule, 3),
		DNS:    &networkmap.DNSConfig{},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-control.streamPublished:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for network snapshot")
	}
	if !latestStreamOptions(t, control).EnableDeviceAliases {
		t.Fatal("daemon lost explicit alias declaration")
	}
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlSession != ControlSessionSynchronized ||
		status.NetmapRevision != 7 ||
		status.NetworkName != "network.example.mesh" ||
		len(status.SelfAddresses) != 1 ||
		status.SelfAddresses[0] != "100.64.0.1/32" ||
		status.PeerCount != 2 || status.PolicyRuleCount != 3 ||
		status.DataPlane != string(dataplane.StateTUNReady) ||
		status.DNS != DNSConfigured {
		t.Fatalf("sync status = %#v", status)
	}
	status.SelfAddresses[0] = "mutated"
	secondStatus, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("second Status() error = %v", err)
	}
	if secondStatus.SelfAddresses[0] != "100.64.0.1/32" {
		t.Fatalf("status self addresses leaked mutable state: %#v", secondStatus.SelfAddresses)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if dataPlane.applyCalls != 1 || dataPlane.closeCalls != 1 {
		t.Fatalf("data plane calls apply=%d close=%d, want 1/1", dataPlane.applyCalls, dataPlane.closeCalls)
	}
	if dns.applyCalls != 1 || dns.resetCalls != 0 || dns.closeCalls != 1 {
		t.Fatalf("dns calls apply=%d reset=%d close=%d, want 1/0/1", dns.applyCalls, dns.resetCalls, dns.closeCalls)
	}
}

func TestService_RunRecoversRuntimeApplyFailuresWithBoundedBackoff(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	applyErr := errors.New("test helper temporarily unavailable")
	dataPlane := &fakeDataPlane{
		applyErrors: []error{
			applyErr,
			applyErr,
			applyErr,
			applyErr,
			applyErr,
			applyErr,
			applyErr,
		},
	}
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	var retryBases []time.Duration
	service.runtimeRetryDelay = func(base time.Duration) time.Duration {
		retryBases = append(retryBases, base)

		return 0
	}
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: []networkmap.Node{{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}},
		Policy: []networkmap.Rule{{}},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-control.streamPublished:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for recovered network snapshot")
	}

	wantBases := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		maxRuntimeRetry,
		maxRuntimeRetry,
	}
	if !slices.Equal(retryBases, wantBases) {
		t.Fatalf("runtime retry bases = %v, want %v", retryBases, wantBases)
	}
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlSession != ControlSessionSynchronized ||
		status.DataPlane != string(dataplane.StateTUNReady) {
		t.Fatalf("recovered status = %#v", status)
	}
	if status.RuntimeRecovery.Failures != 7 ||
		status.RuntimeRecovery.Recoveries != 1 ||
		status.RuntimeRecovery.Pending {
		t.Fatalf("runtime recovery status = %#v", status.RuntimeRecovery)
	}
	if dataPlane.applyCalls != 8 || dataPlane.closeCalls != 7 {
		t.Fatalf(
			"runtime calls before shutdown apply=%d close=%d, want 8/7",
			dataPlane.applyCalls,
			dataPlane.closeCalls,
		)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if dataPlane.closeCalls != 8 {
		t.Fatalf("data plane close calls after shutdown = %d, want 8", dataPlane.closeCalls)
	}
}

func TestService_RuntimeRecoveryStatusTracksPendingAndSuccess(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	service.dataPlane = &fakeDataPlane{
		applyErrors: []error{errors.New("test helper temporarily unavailable")},
	}
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	retryStarted := make(chan struct{})
	service.runtimeRetryDelay = func(time.Duration) time.Duration {
		close(retryStarted)

		return time.Hour
	}
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-retryStarted:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for runtime recovery")
	}

	status, err := service.Status(t.Context())
	if err != nil {
		cancel()
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlSession != ControlSessionConnecting ||
		status.RuntimeRecovery.Failures != 1 ||
		status.RuntimeRecovery.Recoveries != 0 ||
		!status.RuntimeRecovery.Pending {
		cancel()
		t.Fatalf("pending runtime recovery status = %#v", status)
	}

	service.signalControlSync()
	select {
	case <-control.streamPublished:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for recovered network snapshot")
	}
	status, err = service.Status(t.Context())
	if err != nil {
		cancel()
		t.Fatalf("Status() after recovery error = %v", err)
	}
	if status.ControlSession != ControlSessionSynchronized ||
		status.RuntimeRecovery.Failures != 1 ||
		status.RuntimeRecovery.Recoveries != 1 ||
		status.RuntimeRecovery.Pending {
		cancel()
		t.Fatalf("completed runtime recovery status = %#v", status)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestService_RunStopsWhenRuntimeCleanupIsAmbiguous(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	applyErr := errors.New("test helper temporarily unavailable")
	closeErr := errors.New("test tun close failed")
	dataPlane := &fakeDataPlane{
		applyErrors: []error{applyErr},
		closeErrors: []error{closeErr},
	}
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	retryCalled := false
	service.runtimeRetryDelay = func(time.Duration) time.Duration {
		retryCalled = true

		return 0
	}
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Peers:    []networkmap.Node{{}},
		Policy:   []networkmap.Rule{{}},
	}

	err := service.Run(t.Context())
	if !errors.Is(err, closeErr) {
		t.Fatalf("Run() error = %v, want cleanup failure", err)
	}
	if retryCalled {
		t.Fatal("ambiguous cleanup entered the runtime retry loop")
	}
	if dataPlane.applyCalls != 1 || dataPlane.closeCalls != 2 {
		t.Fatalf(
			"runtime calls apply=%d close=%d, want 1/2",
			dataPlane.applyCalls,
			dataPlane.closeCalls,
		)
	}
}

func TestService_WaitForRuntimeRecoveryInterruptsImmediately(t *testing.T) {
	t.Parallel()

	service := &Service{
		runtimeRetryDelay: func(time.Duration) time.Duration { return time.Hour },
		syncSignal:        make(chan struct{}, 1),
	}
	done := make(chan error, 1)
	go func() {
		elapsed, err := service.waitForRuntimeRecovery(t.Context(), minRuntimeRetry)
		if elapsed {
			done <- errors.New("runtime retry unexpectedly elapsed")

			return
		}
		done <- err
	}()
	service.signalControlSync()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForRuntimeRecovery() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("state change did not interrupt runtime recovery wait")
	}
}

func TestService_WaitForRuntimeRecoveryHonorsCancellation(t *testing.T) {
	t.Parallel()

	service := &Service{
		runtimeRetryDelay: func(time.Duration) time.Duration { return time.Hour },
		syncSignal:        make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := service.waitForRuntimeRecovery(ctx, minRuntimeRetry)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitForRuntimeRecovery() error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt runtime recovery wait")
	}
}

func TestRuntimeRetryAfterSessionRequiresStableWindow(t *testing.T) {
	t.Parallel()

	synchronizedAt := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name           string
		synchronizedAt time.Time
		now            time.Time
		want           time.Duration
	}{
		{
			name: "no synchronized map",
			now:  synchronizedAt.Add(time.Hour),
			want: maxRuntimeRetry,
		},
		{
			name:           "flapping session",
			synchronizedAt: synchronizedAt,
			now:            synchronizedAt.Add(runtimeRetryReset - time.Nanosecond),
			want:           maxRuntimeRetry,
		},
		{
			name:           "stable session",
			synchronizedAt: synchronizedAt,
			now:            synchronizedAt.Add(runtimeRetryReset),
			want:           minRuntimeRetry,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := runtimeRetryAfterSession(
				maxRuntimeRetry,
				test.synchronizedAt,
				test.now,
			)
			if got != test.want {
				t.Fatalf("runtimeRetryAfterSession() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestService_RunDoesNotRetryPermanentControlFailure(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamError = controlplane.ErrControlKeyChanged

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	waitForStreamStart(t, control)
	waitForControlSession(t, service, ControlSessionBlocked)
	select {
	case <-control.streamStarted:
		cancel()
		<-runResult
		t.Fatal("permanent control failure opened another stream")
	case <-time.After(25 * time.Millisecond):
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestService_RunWaitsWhileSuspendedAndRetries(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	var retryBases []time.Duration
	var mu sync.Mutex
	service.runtimeRetryDelay = func(base time.Duration) time.Duration {
		mu.Lock()
		defer mu.Unlock()
		retryBases = append(retryBases, base)

		return 0
	}
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.mu.Lock()
	control.streamError = fmt.Errorf("%w: control endpoint returned http 423", controlplane.ErrNetmapAuthorityPaused)
	control.mu.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	waitForStreamStart(t, control)
	waitForStreamStart(t, control)
	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Just suspended: retry quickly so a resume takes effect within seconds.
	if len(retryBases) == 0 || retryBases[0] != suspendedRetryFast {
		t.Fatalf("retry bases = %v, want the fast suspended retry", retryBases)
	}
	if failures := service.runtimeFailures.Load(); failures != 0 {
		t.Fatalf("suspension counted %d runtime failures, want 0", failures)
	}
}

func TestService_RunRejectsConcurrentSupervisor(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() { firstDone <- service.Run(ctx) }()
	waitForStreamStart(t, control)

	secondDone := make(chan error, 1)
	go func() { secondDone <- service.Run(ctx) }()
	var secondErr error
	duplicateStarted := false
	select {
	case secondErr = <-secondDone:
	case <-control.streamStarted:
		duplicateStarted = true
	case <-time.After(time.Second):
		secondErr = errors.New("concurrent Run did not return")
	}

	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first Run() error = %v, want context cancellation", err)
	}
	if duplicateStarted {
		if err := <-secondDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("duplicate Run() error = %v, want context cancellation", err)
		}
		t.Fatal("concurrent Run opened a duplicate control session")
	}
	if !errors.Is(secondErr, ErrServiceRunning) {
		t.Fatalf("concurrent Run() error = %v, want ErrServiceRunning", secondErr)
	}

	restartCtx, cancelRestart := context.WithCancel(t.Context())
	restartDone := make(chan error, 1)
	go func() { restartDone <- service.Run(restartCtx) }()
	waitForStreamStart(t, control)
	cancelRestart()
	if err := <-restartDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("restarted Run() error = %v, want context cancellation", err)
	}
}

func TestService_RunRotatesPeerProbeDiscoKey(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	created := make(chan key.DiscoPrivate, 2)
	service.newDiscoKey = func() (key.DiscoPrivate, error) {
		disco, err := key.NewDiscoPrivate()
		if err == nil {
			created <- disco
		}

		return disco, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()

	first := waitForDiscoKey(t, created)
	waitForStreamStart(t, control)
	firstOptions := latestStreamOptions(t, control)
	if firstOptions.PeerProbePublicKey != peerprobe.MapDiscoveryKey(first.Public()) {
		t.Fatalf("first peer-probe key = %q", firstOptions.PeerProbePublicKey)
	}

	service.signalControlSync()
	second := waitForDiscoKey(t, created)
	waitForStreamStart(t, control)
	secondOptions := latestStreamOptions(t, control)
	if secondOptions.PeerProbePublicKey != peerprobe.MapDiscoveryKey(second.Public()) {
		t.Fatalf("second peer-probe key = %q", secondOptions.PeerProbePublicKey)
	}
	if firstOptions.PeerProbePublicKey == secondOptions.PeerProbePublicKey {
		t.Fatal("disco key did not rotate with the control session")
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestService_RunFailsClosedWithoutPeerProbeIdentity(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	identityErr := errors.New("test entropy unavailable")
	service.newDiscoKey = func() (key.DiscoPrivate, error) {
		return key.DiscoPrivate{}, identityErr
	}
	if err := service.Run(t.Context()); !errors.Is(err, identityErr) {
		t.Fatalf("Run() error = %v, want identity failure", err)
	}
	control.mu.Lock()
	streamCalls := len(control.streamOptions)
	control.mu.Unlock()
	if streamCalls != 0 {
		t.Fatalf("control stream calls = %d, want 0", streamCalls)
	}
}

func TestService_RunAttachesAndSchedulesLivePeerProbes(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	dataPlane := newFakeLiveProbeDataPlane()
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}

	localProbe, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatalf("NewDiscoPrivate(local) error = %v", err)
	}
	remoteProbe, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatalf("NewDiscoPrivate(remote) error = %v", err)
	}
	service.newDiscoKey = func() (key.DiscoPrivate, error) { return localProbe, nil }
	peerEndpoint := netip.MustParseAddrPort("203.0.113.80:41641")
	control.mu.Lock()
	control.echoPeerProbeKey = true
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID:                1,
			PublicKey:         "nodekey:" + strings.Repeat("11", 32),
			MachineAuthorized: true,
		},
		Peers: []networkmap.Node{{
			ID:                2,
			PublicKey:         "nodekey:" + strings.Repeat("22", 32),
			DiscoveryKey:      peerprobe.MapDiscoveryKey(remoteProbe.Public()),
			Endpoints:         []netip.AddrPort{peerEndpoint},
			MachineAuthorized: true,
		}},
	}
	control.mu.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	scheduled := waitForLiveProbeSend(t, dataPlane)
	if scheduled.destination != peerEndpoint || scheduled.socket != dataPlane.socket {
		t.Fatalf("scheduled probe = %#v", scheduled)
	}
	remoteChannel, err := disco.NewPeerKey(remoteProbe, localProbe.Public())
	if err != nil {
		t.Fatalf("remote NewPeerKey() error = %v", err)
	}
	message, err := remoteChannel.Open(scheduled.packet)
	if err != nil {
		t.Fatalf("remote Open(scheduled ping) error = %v", err)
	}
	ping, ok := message.(disco.Ping)
	if !ok || ping.Node != mustDaemonNodeKey(t, control.streamSnapshot.Self.PublicKey) {
		t.Fatalf("remote Open(scheduled ping) = %#v", message)
	}
	authenticatedPong, err := remoteChannel.Seal(nil, disco.Pong{
		TxID:     ping.TxID,
		Observed: netip.MustParseAddrPort("198.51.100.80:41641"),
	}, rand.Reader)
	if err != nil {
		t.Fatalf("remote Seal(pong) error = %v", err)
	}
	handler := dataPlane.handlerSnapshot()
	if handler == nil {
		t.Fatal("peer-probe handler was not attached")
	}
	handler.HandleDatagram(authenticatedPong, peerEndpoint, dataPlane.socket)
	endpointUpdate := waitForEndpointUpdate(t, dataPlane.endpointUpdates)
	if endpointUpdate.restore || endpointUpdate.revision != 1 ||
		endpointUpdate.peerID != 2 || endpointUpdate.endpoint != peerEndpoint {
		t.Fatalf("authenticated endpoint update = %#v", endpointUpdate)
	}

	remotePingID := disco.TxID{9, 8, 7, 6, 5, 4, 3, 2, 1, 4, 5, 6}
	remotePing, err := remoteChannel.Seal(nil, disco.Ping{
		TxID: remotePingID,
		Node: mustDaemonNodeKey(t, control.streamSnapshot.Peers[0].PublicKey),
	}, rand.Reader)
	if err != nil {
		t.Fatalf("remote Seal(ping) error = %v", err)
	}
	handler.HandleDatagram(remotePing, peerEndpoint, dataPlane.socket)
	replied := waitForLiveProbeSend(t, dataPlane)
	if replied.destination != peerEndpoint {
		t.Fatalf("pong destination = %v, want %v", replied.destination, peerEndpoint)
	}
	message, err = remoteChannel.Open(replied.packet)
	if err != nil {
		t.Fatalf("remote Open(pong) error = %v", err)
	}
	pong, ok := message.(disco.Pong)
	if !ok || pong.TxID != remotePingID || pong.Observed != peerEndpoint {
		t.Fatalf("remote Open(pong) = %#v", message)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if dataPlane.handlerSnapshot() != nil {
		t.Fatal("peer-probe handler remained attached after shutdown")
	}
}

func TestService_RunDiscoversAndPublishesDirectEndpoint(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	reflexive, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.20:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{reflexive})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	dataPlane := &fakeEndpointDataPlane{
		discoveryResult: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: []networkmap.Node{{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}},
		Relays: map[int]networkmap.RelayRegion{
			1: {
				ID: 1,
				Nodes: []networkmap.RelayNode{{
					Name: "relay-1",
					IPv4: "192.0.2.10",
				}},
			},
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-control.endpointPublished:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for endpoint publication")
	}

	control.mu.Lock()
	updates := append([]controlplane.EndpointUpdate(nil), control.endpointUpdates...)
	control.mu.Unlock()
	if len(updates) != 1 || !updates[0].Candidates.Equal(candidates) ||
		updates[0].PreferredRelay != 1 {
		t.Fatalf("endpoint updates = %#v", updates)
	}
	if dataPlane.discoveryScope == 0 ||
		!slices.Equal(dataPlane.discoveryServers, []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:3478"),
		}) {
		t.Fatalf(
			"discovery scope=%d servers=%v",
			dataPlane.discoveryScope,
			dataPlane.discoveryServers,
		)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshRunsPeriodicallyWithoutDuplicatePublication(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.50:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 4),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return 5 * time.Millisecond },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 11, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active:   true,
		periodic: true,
		servers: []pathdiscovery.RelayServer{{
			RegionID: 1,
			Endpoint: netip.MustParseAddrPort("192.0.2.50:3478"),
		}},
	}

	select {
	case update := <-updates:
		if !update.Candidates.Equal(candidates) {
			t.Fatalf("first endpoint update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first endpoint update")
	}
	for range 2 {
		select {
		case <-discoverer.calls:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for periodic discovery")
		}
	}
	select {
	case duplicate := <-updates:
		t.Fatalf("received duplicate endpoint update %#v", duplicate)
	default:
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshDoesNotPollWithoutPeers(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.53:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 2),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return 5 * time.Millisecond },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 16, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{active: true}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for peerless endpoint update")
	}
	select {
	case <-discoverer.calls:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial peerless discovery")
	}
	select {
	case <-discoverer.calls:
		t.Fatal("peerless endpoint discovery polled periodically")
	case <-time.After(25 * time.Millisecond):
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshRunsImmediatelyAfterNetworkChange(t *testing.T) {
	t.Parallel()

	firstCandidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.51:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	firstCandidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{firstCandidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	secondCandidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.52:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	secondCandidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{secondCandidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 2),
		result: pathdiscovery.DiscoveryResult{Candidates: firstCandidates},
	}
	networkChanges := make(chan struct{}, 1)
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
		networkChanges:       networkChanges,
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 15, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{active: true}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial endpoint update")
	}

	discoverer.mu.Lock()
	discoverer.result = pathdiscovery.DiscoveryResult{Candidates: secondCandidates}
	discoverer.mu.Unlock()
	networkChanges <- struct{}{}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for network-triggered endpoint update")
	}
	if observed := service.networkObserved.Load(); observed != 1 {
		t.Fatalf("network changes observed = %d, want 1", observed)
	}
	if refreshes := service.networkRefreshes.Load(); refreshes != 1 {
		t.Fatalf("network endpoint refreshes = %d, want 1", refreshes)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshSelectsMeasuredHomeRelay(t *testing.T) {
	t.Parallel()

	firstServer := netip.MustParseAddrPort("192.0.2.71:3478")
	secondServer := netip.MustParseAddrPort("192.0.2.72:3478")
	discoverer := &refreshDiscoverer{
		calls: make(chan struct{}, 4),
		result: pathdiscovery.DiscoveryResult{ServerLatencies: []pathdiscovery.ServerLatency{
			{Server: firstServer, Latency: 100 * time.Millisecond},
			{Server: secondServer, Latency: 20 * time.Millisecond},
		}},
		health: relay.HealthSnapshot{
			Available:  true,
			HomeRegion: 1,
			Regions: []relay.RegionHealth{{
				RegionID:      1,
				Connected:     true,
				LastConnected: time.Now().Add(-time.Second),
				LastActivity:  time.Now(),
			}},
		},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return 5 * time.Millisecond },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 14, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active:           true,
		periodic:         true,
		controlHomeRelay: 1,
		usableRelays:     []int{1, 2},
		servers: []pathdiscovery.RelayServer{
			{RegionID: 1, Endpoint: firstServer},
			{RegionID: 2, Endpoint: secondServer},
		},
	}

	selected := false
	deadline := time.After(time.Second)
	for !selected {
		select {
		case update := <-updates:
			if update.PreferredRelay == 2 && update.HasPreferredRelay {
				selected = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for prepared preferred relay update")
		}
	}
	discoverer.mu.Lock()
	prepared := append([]int(nil), discoverer.prepared...)
	discoverer.mu.Unlock()
	if !slices.Contains(prepared, 2) {
		t.Fatalf("prepared relay regions = %v, want region 2", prepared)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestRelayRegionLatenciesRejectsUnknownServer(t *testing.T) {
	t.Parallel()

	_, err := relayRegionLatencies(
		[]pathdiscovery.RelayServer{{
			RegionID: 1,
			Endpoint: netip.MustParseAddrPort("192.0.2.81:3478"),
		}},
		[]pathdiscovery.ServerLatency{{
			Server:  netip.MustParseAddrPort("192.0.2.82:3478"),
			Latency: time.Millisecond,
		}},
		[]int{1},
	)
	if err == nil {
		t.Fatal("relayRegionLatencies() error = nil")
	}
}

func TestEndpointRefreshResetWithdrawsDynamicCandidate(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.60:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 1),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 12, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{active: true}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovered endpoint")
	}
	requests <- endpointRefreshRequest{}
	select {
	case update := <-updates:
		if update.Candidates.Len() != 0 || update.PreferredRelay != 0 {
			t.Fatalf("withdrawal = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for endpoint withdrawal")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRequestKeepsPresenceActiveWithoutPeers(t *testing.T) {
	t.Parallel()

	discoverer := &refreshDiscoverer{}
	request, err := endpointRequest(networkmap.Snapshot{}, discoverer)
	if err != nil {
		t.Fatalf("endpointRequest() error = %v", err)
	}
	if !request.active || request.periodic || request.socket != discoverer.DiscoverySocket() {
		t.Fatalf("endpointRequest() = %#v", request)
	}
}

func TestEndpointRefreshSocketChangePublishesReplacementAtomically(t *testing.T) {
	t.Parallel()

	oldCandidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.61:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	oldCandidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{oldCandidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	newCandidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.62:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate(replacement) error = %v", err)
	}
	newCandidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{newCandidate})
	if err != nil {
		t.Fatalf("NewSet(replacement) error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 2),
		result: pathdiscovery.DiscoveryResult{Candidates: oldCandidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 13, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active: true,
		socket: pathdiscovery.Socket{Port: 41641, Generation: 1},
	}
	select {
	case update := <-updates:
		if !update.Candidates.Equal(oldCandidates) {
			t.Fatalf("first endpoint update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovered endpoint")
	}

	discoverer.mu.Lock()
	discoverer.result = pathdiscovery.DiscoveryResult{Candidates: newCandidates}
	discoverer.socket = pathdiscovery.Socket{Port: 41641, Generation: 2}
	discoverer.mu.Unlock()
	requests <- endpointRefreshRequest{
		active: true,
		socket: pathdiscovery.Socket{Port: 41641, Generation: 2},
	}
	select {
	case update := <-updates:
		if !update.Candidates.Equal(newCandidates) {
			t.Fatalf("socket-change replacement = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for socket-change replacement")
	}
	select {
	case update := <-updates:
		t.Fatalf("unexpected intermediate endpoint update = %#v", update)
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestRandomEndpointRefreshDelayBounds(t *testing.T) {
	t.Parallel()

	for range 100 {
		delay := randomEndpointRefreshDelay()
		if delay < minEndpointRefresh || delay >= maxEndpointRefresh {
			t.Fatalf("randomEndpointRefreshDelay() = %v", delay)
		}
	}
}

type refreshDiscoverer struct {
	mu       sync.Mutex
	calls    chan struct{}
	socket   pathdiscovery.Socket
	result   pathdiscovery.DiscoveryResult
	err      error
	health   relay.HealthSnapshot
	prepared []int
}

func (d *refreshDiscoverer) DiscoverySocket() pathdiscovery.Socket {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.socket.IsOpen() {
		return d.socket
	}

	return pathdiscovery.Socket{Port: 41641, Generation: 1}
}

func (d *refreshDiscoverer) DiscoverEndpoints(
	_ context.Context,
	_ uint64,
	_ []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	select {
	case d.calls <- struct{}{}:
	default:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	result := d.result
	result.ServerLatencies = append(
		[]pathdiscovery.ServerLatency(nil),
		d.result.ServerLatencies...,
	)

	return result, d.err
}

func (d *refreshDiscoverer) RelayHealth() relay.HealthSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	health := d.health
	health.Regions = append([]relay.RegionHealth(nil), d.health.Regions...)

	return health
}

func (d *refreshDiscoverer) PrepareRelayRegion(regionID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prepared = append(d.prepared, regionID)
	now := time.Now()
	for index := range d.health.Regions {
		if d.health.Regions[index].RegionID == regionID {
			d.health.Regions[index].Connected = true
			d.health.Regions[index].LastConnected = now
			d.health.Regions[index].LastActivity = now

			return nil
		}
	}
	d.health.Regions = append(d.health.Regions, relay.RegionHealth{
		RegionID:      regionID,
		Connected:     true,
		LastConnected: now,
		LastActivity:  now,
	})

	return nil
}

func TestService_StatusReportsOnlineForEncryptedDataPlane(t *testing.T) {
	t.Parallel()

	service, _, _, profileID, _ := newTestService(t)
	service.setSyncStatus(syncStatus{
		profileID: profileID,
		state:     ControlSessionSynchronized,
		dataPlane: string(dataplane.StateEncrypted),
	})

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StateOnline || status.DataPlane != string(dataplane.StateEncrypted) {
		t.Fatalf("Status() = %#v, want online encrypted data plane", status)
	}
}

func TestService_StatusReportsOnlineForSynchronizedPeerlessControl(t *testing.T) {
	t.Parallel()

	service, _, _, profileID, _ := newTestService(t)
	service.setSyncStatus(syncStatus{
		profileID: profileID,
		state:     ControlSessionSynchronized,
		dataPlane: string(dataplane.StateIdle),
		peerCount: 0,
	})

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StateOnline {
		t.Fatalf("Status().State = %q, want %q", status.State, StateOnline)
	}
}

func TestService_StatusReportsOfflineUntilControlIsSynchronized(t *testing.T) {
	t.Parallel()

	service, _, _, profileID, _ := newTestService(t)
	service.setSyncStatus(syncStatus{
		profileID: profileID,
		state:     ControlSessionConnecting,
		dataPlane: string(dataplane.StateEncrypted),
	})

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StateOffline {
		t.Fatalf("Status().State = %q, want %q", status.State, StateOffline)
	}
}

func TestService_StatusReportsNetworkChangeCounters(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	service.networkChanges = make(chan struct{})
	service.networkObserved.Store(4)
	service.networkRefreshes.Store(3)

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.NetworkChanges.Available || status.NetworkChanges.Observed != 4 ||
		status.NetworkChanges.EndpointRefreshes != 3 {
		t.Fatalf("network change status = %#v", status.NetworkChanges)
	}
}

func TestService_StatusReportsRuntimeRecoveryCounters(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	service.runtimeFailures.Store(4)
	service.runtimeRecoveries.Store(3)
	service.runtimePending.Store(true)

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.RuntimeRecovery.Failures != 4 ||
		status.RuntimeRecovery.Recoveries != 3 ||
		!status.RuntimeRecovery.Pending {
		t.Fatalf("runtime recovery status = %#v", status.RuntimeRecovery)
	}
}

func TestService_StatusReportsRuntimeHealth(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Runtime.Goroutines == 0 || status.Runtime.HeapAllocBytes == 0 ||
		status.Runtime.HeapObjects == 0 || status.Runtime.SysBytes == 0 {
		t.Fatalf("runtime health = %#v, want populated aggregate counters", status.Runtime)
	}
}

func TestService_StatusReportsAggregateTransportState(t *testing.T) {
	t.Parallel()

	service, _, _, profileID, _ := newTestService(t)
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	dataPlane := &fakeDataPlane{
		peerPaths: dataplane.PeerPathSnapshot{
			Available:   true,
			PeerCount:   2,
			DirectCount: 1,
			RelayCount:  1,
		},
		relayStatus: relay.HealthSnapshot{
			Available:  true,
			HomeRegion: 7,
			Regions: []relay.RegionHealth{{
				RegionID:      7,
				Connected:     true,
				LastConnected: now,
			}},
		},
	}
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		profileID: profileID,
		state:     ControlSessionSynchronized,
		dataPlane: string(dataplane.StateEncryptedRelay),
	})

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.PeerPaths != dataPlane.peerPaths || !status.Relay.Available ||
		status.Relay.HomeRegion != 7 || len(status.Relay.Regions) != 1 {
		t.Fatalf("Status() transport state = %#v, %#v", status.PeerPaths, status.Relay)
	}
	status.Relay.Regions[0].Connected = false
	if second, err := service.Status(t.Context()); err != nil {
		t.Fatalf("second Status() error = %v", err)
	} else if !second.Relay.Regions[0].Connected {
		t.Fatal("Status() returned mutable relay state")
	}
}

const testFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeControl struct {
	mu                  sync.Mutex
	bootstrapCalls      int
	verifyCalls         int
	registrationResults []controlplane.RegistrationResult
	registerOptions     []controlplane.RegisterOptions
	registerMaterial    controlplane.KeyMaterial
	rotationKeys        [][]byte
	rotationMaterials   []controlplane.KeyMaterial
	rotationResults     []controlplane.RegistrationResult
	rotateFunc          func(
		context.Context,
		[]byte,
	) (controlplane.RegistrationResult, error)
	registerFunc func(
		context.Context,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error)
	streamSnapshot    *networkmap.Snapshot
	streamPublished   chan struct{}
	endpointPublished chan struct{}
	endpointUpdates   []controlplane.EndpointUpdate
	streamOptions     []controlplane.NetmapOptions
	streamStarted     chan struct{}
	streamError       error
	echoPeerProbeKey  bool
}

type fakeDataPlane struct {
	applyCalls  int
	applyErrors []error
	closeCalls  int
	closeErrors []error
	peerPaths   dataplane.PeerPathSnapshot
	relayStatus relay.HealthSnapshot
}

type fakeDNS struct {
	applyCalls int
	resetCalls int
	closeCalls int
	configured bool
}

func (f *fakeDNS) Apply(context.Context, networkmap.Snapshot) (bool, error) {
	f.applyCalls++

	return f.configured, nil
}

func (f *fakeDNS) Reset(context.Context) error {
	f.resetCalls++

	return nil
}

func (f *fakeDNS) Close(context.Context) error {
	f.closeCalls++

	return nil
}

func (f *fakeDataPlane) Apply(
	_ context.Context,
	_ networkmap.Snapshot,
	_ dataplane.NodePrivateKey,
) (dataplane.State, error) {
	f.applyCalls++
	if len(f.applyErrors) != 0 {
		err := f.applyErrors[0]
		f.applyErrors = f.applyErrors[1:]
		if err != nil {
			return dataplane.StateFailed, err
		}
	}

	return dataplane.StateTUNReady, nil
}

func (f *fakeDataPlane) Close() error {
	f.closeCalls++
	if len(f.closeErrors) != 0 {
		err := f.closeErrors[0]
		f.closeErrors = f.closeErrors[1:]

		return err
	}

	return nil
}

func (f *fakeDataPlane) PeerPaths() dataplane.PeerPathSnapshot {
	return f.peerPaths
}

func (f *fakeDataPlane) RelayHealth() relay.HealthSnapshot {
	return f.relayStatus
}

func (f *fakeControl) Probe(context.Context, string) (controlplane.Result, error) {
	return controlplane.Result{}, nil
}

func (f *fakeControl) BootstrapTrust(context.Context, string, string) (controlplane.TrustResult, error) {
	f.bootstrapCalls++

	return controlplane.TrustResult{
		Fingerprint: testFingerprint,
		Material: controlplane.KeyMaterial{
			MachinePrivateKey: []byte("machine-private"),
			NodePrivateKey:    []byte("privkey:" + strings.Repeat("01", 32)),
			ControlPublicKey:  []byte("control-public"),
		},
	}, nil
}

func (f *fakeControl) VerifyTrust(context.Context, string, controlplane.KeyMaterial, string) error {
	f.verifyCalls++

	return nil
}

func (f *fakeControl) Register(
	ctx context.Context,
	_ string,
	material controlplane.KeyMaterial,
	options controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	f.mu.Lock()
	f.registerMaterial = material
	f.registerOptions = append(f.registerOptions, options)
	registerFunc := f.registerFunc
	if registerFunc != nil {
		f.mu.Unlock()

		return registerFunc(ctx, options)
	}
	if len(f.registrationResults) == 0 {
		f.mu.Unlock()

		return controlplane.RegistrationResult{}, errors.New("unexpected registration call")
	}
	result := f.registrationResults[0]
	f.registrationResults = f.registrationResults[1:]
	f.mu.Unlock()

	return result, nil
}

func (f *fakeControl) RotateNodeKey(
	ctx context.Context,
	_ string,
	material controlplane.KeyMaterial,
	newNodePrivateKey []byte,
	_ controlplane.RegisterOptions,
) (controlplane.RegistrationResult, error) {
	f.mu.Lock()
	f.rotationKeys = append(f.rotationKeys, append([]byte(nil), newNodePrivateKey...))
	f.rotationMaterials = append(f.rotationMaterials, controlplane.KeyMaterial{
		MachinePrivateKey: append([]byte(nil), material.MachinePrivateKey...),
		NodePrivateKey:    append([]byte(nil), material.NodePrivateKey...),
		ControlPublicKey:  append([]byte(nil), material.ControlPublicKey...),
	})
	rotateFunc := f.rotateFunc
	if rotateFunc != nil {
		f.mu.Unlock()

		return rotateFunc(ctx, append([]byte(nil), newNodePrivateKey...))
	}
	if len(f.rotationResults) == 0 {
		f.mu.Unlock()

		return controlplane.RegistrationResult{}, errors.New("unexpected Node-key rotation call")
	}
	result := f.rotationResults[0]
	f.rotationResults = f.rotationResults[1:]
	f.mu.Unlock()

	return result, nil
}

func (f *fakeControl) StreamNetmap(
	ctx context.Context,
	_ string,
	_ controlplane.KeyMaterial,
	options controlplane.NetmapOptions,
	handler controlplane.NetmapHandler,
) error {
	f.mu.Lock()
	snapshot := f.streamSnapshot
	streamError := f.streamError
	echoPeerProbeKey := f.echoPeerProbeKey
	published := f.streamPublished
	f.streamOptions = append(f.streamOptions, options)
	started := f.streamStarted
	f.mu.Unlock()
	select {
	case started <- struct{}{}:
	default:
	}
	if streamError != nil {
		return streamError
	}
	if snapshot != nil {
		current := *snapshot
		if echoPeerProbeKey {
			current.Self.DiscoveryKey = options.PeerProbePublicKey
		}
		if err := handler(ctx, current); err != nil {
			return fmt.Errorf("%w: %w", controlplane.ErrNetmapConsumer, err)
		}
		select {
		case published <- struct{}{}:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update, open := <-options.EndpointUpdates:
			if !open {
				options.EndpointUpdates = nil

				continue
			}
			f.mu.Lock()
			f.endpointUpdates = append(f.endpointUpdates, update)
			endpointPublished := f.endpointPublished
			f.mu.Unlock()
			select {
			case endpointPublished <- struct{}{}:
			default:
			}
		}
	}
}

type fakeEndpointDataPlane struct {
	fakeDataPlane
	discoveryScope   uint64
	discoveryServers []netip.AddrPort
	discoveryResult  pathdiscovery.DiscoveryResult
	discoveryErr     error
}

type liveProbeSend struct {
	packet      []byte
	destination netip.AddrPort
	socket      pathdiscovery.Socket
}

type fakeLiveProbeDataPlane struct {
	mu              sync.Mutex
	socket          pathdiscovery.Socket
	handler         pathdiscovery.DatagramHandler
	sends           chan liveProbeSend
	endpointUpdates chan endpointUpdate
	closed          int
}

func newFakeLiveProbeDataPlane() *fakeLiveProbeDataPlane {
	return &fakeLiveProbeDataPlane{
		socket:          pathdiscovery.Socket{Port: 41641, Generation: 1},
		sends:           make(chan liveProbeSend, 8),
		endpointUpdates: make(chan endpointUpdate, 8),
	}
}

func (*fakeLiveProbeDataPlane) Apply(
	context.Context,
	networkmap.Snapshot,
	dataplane.NodePrivateKey,
) (dataplane.State, error) {
	return dataplane.StateEncrypted, nil
}

func (d *fakeLiveProbeDataPlane) Close() error {
	d.mu.Lock()
	d.closed++
	d.mu.Unlock()

	return nil
}

func (d *fakeLiveProbeDataPlane) Socket() pathdiscovery.Socket {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.socket
}

func (d *fakeLiveProbeDataPlane) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	d.mu.Lock()
	socket := d.socket
	d.mu.Unlock()
	d.sends <- liveProbeSend{
		packet:      bytes.Clone(packet),
		destination: destination,
		socket:      socket,
	}

	return socket, nil
}

func (d *fakeLiveProbeDataPlane) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) error {
	d.mu.Lock()
	d.handler = handler
	d.mu.Unlock()

	return nil
}

func (d *fakeLiveProbeDataPlane) SetPreferredEndpoint(
	revision uint64,
	peerID uint64,
	endpoint netip.AddrPort,
) error {
	d.endpointUpdates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		endpoint: endpoint,
	}

	return nil
}

func (d *fakeLiveProbeDataPlane) RestorePreferredEndpoint(
	revision uint64,
	peerID uint64,
) error {
	d.endpointUpdates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		restore:  true,
	}

	return nil
}

func (d *fakeLiveProbeDataPlane) handlerSnapshot() pathdiscovery.DatagramHandler {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.handler
}

func waitForLiveProbeSend(
	t *testing.T,
	dataPlane *fakeLiveProbeDataPlane,
) liveProbeSend {
	t.Helper()

	select {
	case sent := <-dataPlane.sends:
		return sent
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for live peer-probe send")

		return liveProbeSend{}
	}
}

func mustDaemonNodeKey(t *testing.T, text string) key.NodePublic {
	t.Helper()

	encoded, ok := strings.CutPrefix(text, "nodekey:")
	raw, err := hex.DecodeString(encoded)
	if !ok || err != nil || len(raw) != 32 {
		t.Fatalf("node key %q is malformed", text)
	}

	return key.NodePublic(raw)
}

func (f *fakeEndpointDataPlane) DiscoverySocket() pathdiscovery.Socket {
	return pathdiscovery.Socket{Port: 41641, Generation: 1}
}

func (f *fakeEndpointDataPlane) DiscoverEndpoints(
	_ context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	f.discoveryScope = scope
	f.discoveryServers = append([]netip.AddrPort(nil), servers...)

	return f.discoveryResult, f.discoveryErr
}

func newTestService(t *testing.T) (*Service, *identity.Store, *fakeControl, string, string) {
	t.Helper()

	stateDir := t.TempDir()
	profiles, err := profile.Open(stateDir)
	if err != nil {
		t.Fatalf("profile.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = profiles.Close() })
	created, err := profiles.Create(t.Context(), profile.CreateInput{
		Name:       "test",
		ControlURL: "https://control.example.com",
	})
	if err != nil {
		t.Fatalf("profiles.Create() error = %v", err)
	}
	protector, err := secretstore.New(bytes.Repeat([]byte{0x51}, secretstore.KeySize))
	if err != nil {
		t.Fatalf("secretstore.New() error = %v", err)
	}
	identities, err := identity.Open(stateDir, protector)
	if err != nil {
		_ = protector.Close()
		t.Fatalf("identity.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = identities.Close() })
	control := &fakeControl{
		streamPublished:   make(chan struct{}, 1),
		endpointPublished: make(chan struct{}, 1),
		streamStarted:     make(chan struct{}, 4),
	}
	service, err := New(
		profiles,
		identities,
		version.Info{Version: "test"},
		control,
		Options{
			Hostname: "node-a",
			Clock:    time.Now,
		},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return service, identities, control, created.ID, stateDir
}

func waitForStreamStart(t *testing.T, control *fakeControl) {
	t.Helper()

	select {
	case <-control.streamStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for control stream start")
	}
}

func waitForControlSession(t *testing.T, service *Service, want string) {
	t.Helper()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := service.Status(t.Context())
		if err != nil {
			t.Fatalf("Status() error = %v", err)
		}
		if status.ControlSession == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf(
				"timed out waiting for control session %q; last state %q",
				want,
				status.ControlSession,
			)
		case <-ticker.C:
		}
	}
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = bytes.Clone(value)
	}

	return cloned
}

func clearByteSlices(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}

func cloneProtocolMaterials(values []controlplane.KeyMaterial) []controlplane.KeyMaterial {
	cloned := make([]controlplane.KeyMaterial, len(values))
	for index, value := range values {
		cloned[index] = controlplane.KeyMaterial{
			MachinePrivateKey: bytes.Clone(value.MachinePrivateKey),
			NodePrivateKey:    bytes.Clone(value.NodePrivateKey),
			ControlPublicKey:  bytes.Clone(value.ControlPublicKey),
		}
	}

	return cloned
}

func clearProtocolMaterials(values []controlplane.KeyMaterial) {
	for index := range values {
		clearProtocolMaterial(values[index])
	}
}

func waitForDiscoKey(t *testing.T, created <-chan key.DiscoPrivate) key.DiscoPrivate {
	t.Helper()

	select {
	case disco := <-created:
		return disco
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the session disco key")

		return key.DiscoPrivate{}
	}
}

func latestStreamOptions(t *testing.T, control *fakeControl) controlplane.NetmapOptions {
	t.Helper()

	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.streamOptions) == 0 {
		t.Fatal("control stream options are missing")
	}

	return control.streamOptions[len(control.streamOptions)-1]
}

var _ controlProber = (*fakeControl)(nil)

func TestServiceRejectsAliasAdvertisementWithoutPacketEngine(t *testing.T) {
	t.Parallel()
	service, _, control, _, _ := newTestService(t)
	_, err := New(service.profiles, service.identities, service.build, control, Options{Hostname: "node-a", EnableDeviceAliases: true})
	if err == nil {
		t.Fatal("unsupported alias advertisement accepted")
	}
}

func TestSuspendedRetryDelaySlowsDown(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		suspendedFor time.Duration
		want         time.Duration
	}{
		{0, 3 * time.Second},
		{59 * time.Second, 3 * time.Second},
		{time.Minute, 10 * time.Second},
		{4 * time.Minute, 10 * time.Second},
		{5 * time.Minute, 30 * time.Second},
		{24 * time.Hour, 30 * time.Second},
	} {
		if got := suspendedRetryDelay(test.suspendedFor); got != test.want {
			t.Errorf("suspendedRetryDelay(%s) = %s, want %s", test.suspendedFor, got, test.want)
		}
	}
}
