package meshgw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/k8sstate"
	"meshtransit.net/client/internal/profile"
)

const profileName = "meshgw"

var (
	// ErrStateMismatch means the restored state belongs to another Core
	// than the configured one.
	ErrStateMismatch = errors.New("meshgw: the restored state belongs to another Core")
	// ErrApprovalRequired means the Network wants an administrator to
	// approve new Devices, which a gateway cannot wait for: use a Network
	// without approval for gateways.
	ErrApprovalRequired = errors.New("meshgw: the Network requires an administrator to approve the Device")
	// ErrEnrollmentKey means the replica must register but has no
	// enrollment key.
	ErrEnrollmentKey = errors.New("meshgw: no enrollment key")
)

// controller is the slice of the daemon Enroll drives.
type controller interface {
	ListProfiles(context.Context) (profile.Snapshot, error)
	CreateProfile(context.Context, profile.CreateInput) (profile.Profile, error)
	TrustControl(context.Context, string) (daemon.ControlTrust, error)
	Status(context.Context) (daemon.Status, error)
	StartLogin(context.Context, string) (daemon.Login, error)
	CompleteLogin(context.Context) (daemon.Login, error)
}

// Enroll brings the replica to a registered Device without a person. On a
// first start it creates the profile, pins Core's key to the configured
// fingerprint (never trusting on first use) and registers with the replica's
// enrollment key. With state restored from the Secret it does neither: the
// stored pin is the authority, as it follows Core's key rotations and the
// configured one does not, and the control session checks Core against it.
func Enroll(ctx context.Context, service controller, cfg Config) error {
	status, err := prepareProfile(ctx, service, cfg)
	if err != nil {
		return err
	}
	switch status.Registration {
	case daemon.RegistrationRegistered:
		return nil
	case daemon.RegistrationPending:
		// An administrator may have approved it since, or turned approval
		// off for the Network.
		login, err := service.CompleteLogin(ctx)
		if errors.Is(err, daemon.ErrAuthorizationPending) {
			return ErrApprovalRequired
		}
		if err != nil {
			return fmt.Errorf("meshgw: completing the registration: %w", err)
		}
		return registered(login)
	}

	key, err := readEnrollmentKey(cfg.EnrollmentKeyFile)
	if err != nil {
		return err
	}
	login, err := service.StartLogin(ctx, key)
	if err != nil {
		return fmt.Errorf("meshgw: registering: %w", err)
	}
	return registered(login)
}

// prepareProfile makes the replica's profile and pins Core's key, on a
// first start; with state restored it checks them. It returns the
// registration as the daemon sees it.
func prepareProfile(ctx context.Context, service controller, cfg Config) (daemon.Status, error) {
	snapshot, err := service.ListProfiles(ctx)
	if err != nil {
		return daemon.Status{}, fmt.Errorf("meshgw: reading profiles: %w", err)
	}
	if snapshot.ActiveProfileID == "" {
		if len(snapshot.Profiles) > 0 {
			return daemon.Status{}, fmt.Errorf("%w: profiles but none active", ErrStateMismatch)
		}
		if _, err := service.CreateProfile(ctx, profile.CreateInput{Name: profileName, ControlURL: cfg.ControlURL}); err != nil {
			return daemon.Status{}, fmt.Errorf("meshgw: creating the profile: %w", err)
		}
	} else if active := activeProfile(snapshot); active.ControlURL != cfg.ControlURL {
		return daemon.Status{}, fmt.Errorf("%w: %s, configured %s", ErrStateMismatch, active.ControlURL, cfg.ControlURL)
	}

	status, err := service.Status(ctx)
	if err != nil {
		return daemon.Status{}, fmt.Errorf("meshgw: reading the registration: %w", err)
	}
	if status.ControlTrust != daemon.ControlTrustPinned {
		if _, err := service.TrustControl(ctx, cfg.ControlFingerprint); err != nil {
			return daemon.Status{}, fmt.Errorf("meshgw: checking Core's key: %w", err)
		}
		status.Registration = daemon.RegistrationUnregistered
	}
	return status, nil
}

// registered accepts only a login Core authorized: anything else still
// waits for an administrator.
func registered(login daemon.Login) error {
	if login.State != daemon.RegistrationRegistered {
		return ErrApprovalRequired
	}
	return nil
}

// permanent reports whether an Enroll error stays whatever the retries: the
// pod should then fail, visibly, rather than wait unready. Core failing to
// answer is the one kind that may pass.
func permanent(err error) bool {
	switch {
	case errors.Is(err, controlplane.ErrRegistrationTemporary):
		return false
	case errors.Is(err, ErrJoinRefused), errors.Is(err, daemon.ErrGatewayKeysLost),
		errors.Is(err, daemon.ErrGatewayModeMismatch), errors.Is(err, daemon.ErrNotGateway),
		errors.Is(err, daemon.ErrGatewayStopped):
		return true
	case errors.Is(err, ErrApprovalRequired), errors.Is(err, ErrStateMismatch), errors.Is(err, ErrEnrollmentKey),
		errors.Is(err, k8sstate.ErrConflict), errors.Is(err, daemon.ErrControlTrust),
		errors.Is(err, daemon.ErrControlNotTrusted), errors.Is(err, daemon.ErrRegistration),
		errors.Is(err, profile.ErrInvalid):
		return true
	}
	return false
}

func activeProfile(snapshot profile.Snapshot) profile.Profile {
	for _, item := range snapshot.Profiles {
		if item.ID == snapshot.ActiveProfileID {
			return item
		}
	}
	return profile.Profile{}
}

// readEnrollmentKey reads the replica's enrollment key, only when it must
// register: once used, Core refuses it, and the Secret may be gone.
func readEnrollmentKey(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the mounted enrollment Secret
	if err != nil {
		return "", fmt.Errorf("%w: the replica must register, but %s is unreadable: %w", ErrEnrollmentKey, path, err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrEnrollmentKey, path)
	}
	return key, nil
}
