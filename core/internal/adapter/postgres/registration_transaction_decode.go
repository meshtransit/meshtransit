package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

type registrationCredentialRecord struct {
	internalID          int64
	profileInternalID   int64
	issuerInternalID    int64
	issuerPublicID      string
	state               string
	useLimitKind        string
	maximumUses         sql.NullInt64
	usedCount           int64
	issuedRecoveryEpoch int64
	validFrom           time.Time
	expiresAt           time.Time
	version             int64
}

func (record registrationCredentialRecord) domainValue(
	credentialID enrollment.CredentialID,
	profileID enrollment.ProfileID,
) (enrollment.Credential, error) {
	if record.internalID <= 0 || record.profileInternalID <= 0 || record.issuerInternalID <= 0 ||
		record.version <= 0 {
		return enrollment.Credential{}, ErrRegistrationEvidence
	}
	issuerID, err := identity.ParsePrincipalID(record.issuerPublicID)
	if err != nil {
		return enrollment.Credential{}, ErrRegistrationEvidence
	}
	state, err := registrationCredentialState(record.state)
	if err != nil {
		return enrollment.Credential{}, err
	}
	useLimit, err := registrationUseLimit(record.useLimitKind, record.maximumUses)
	if err != nil {
		return enrollment.Credential{}, err
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  credentialID,
		ProfileID:           profileID,
		IssuerID:            issuerID,
		State:               state,
		UseLimit:            useLimit,
		UsedCount:           record.usedCount,
		IssuedRecoveryEpoch: record.issuedRecoveryEpoch,
		ValidFrom:           record.validFrom,
		ExpiresAt:           record.expiresAt,
	})
	if err != nil {
		return enrollment.Credential{}, ErrRegistrationEvidence
	}
	return credential, nil
}

type registrationProfileRecord struct {
	internalID          int64
	publicID            string
	nodeLifetimeSeconds int64
	ephemeralMode       string
	useLimitKind        string
	maximumUses         sql.NullInt64
	state               string
	version             int64
}

func (record registrationProfileRecord) domainValue(scope network.Scope) (enrollment.Profile, error) {
	if record.internalID <= 0 || record.nodeLifetimeSeconds <= 0 ||
		record.nodeLifetimeSeconds > int64((1<<63-1)/time.Second) || record.version <= 0 {
		return enrollment.Profile{}, ErrRegistrationEvidence
	}
	profileID, err := enrollment.ParseProfileID(record.publicID)
	if err != nil {
		return enrollment.Profile{}, ErrRegistrationEvidence
	}
	state, err := registrationProfileState(record.state)
	if err != nil {
		return enrollment.Profile{}, err
	}
	ephemeralMode, err := registrationEphemeralMode(record.ephemeralMode)
	if err != nil {
		return enrollment.Profile{}, err
	}
	useLimit, err := registrationUseLimit(record.useLimitKind, record.maximumUses)
	if err != nil {
		return enrollment.Profile{}, err
	}
	profile, err := enrollment.NewProfile(enrollment.ProfileParams{
		ID:                 profileID,
		Scope:              scope,
		State:              state,
		NodeLifetime:       time.Duration(record.nodeLifetimeSeconds) * time.Second,
		EphemeralMode:      ephemeralMode,
		CredentialUseLimit: useLimit,
	})
	if err != nil {
		return enrollment.Profile{}, ErrRegistrationEvidence
	}
	return profile, nil
}

type pendingRegistrationRecord struct {
	internalID               int64
	profileInternalID        int64
	credentialInternalID     sql.NullInt64
	intentFormatVersion      int16
	requestHash              []byte
	machineFingerprint       []byte
	requestedNodeKey         []byte
	deviceInternalID         sql.NullInt64
	completedHostname        sql.NullString
	completedDisposition     sql.NullString
	completedNetworkRevision sql.NullInt64
	state                    string
	version                  int64
	createdAt                time.Time
	expiresAt                time.Time
}

func (record pendingRegistrationRecord) domainValue(
	registrationID enrollment.RegistrationID,
	scope network.Scope,
	profileID enrollment.ProfileID,
) (enrollment.Registration, error) {
	if record.internalID <= 0 || record.profileInternalID <= 0 ||
		record.intentFormatVersion != 2 || record.version <= 0 {
		return enrollment.Registration{}, ErrRegistrationEvidence
	}
	fingerprint, err := registrationBytes32(record.machineFingerprint)
	if err != nil {
		return enrollment.Registration{}, err
	}
	state, err := registrationPendingState(record.state)
	if err != nil {
		return enrollment.Registration{}, err
	}
	var nodeID node.ID
	if state == enrollment.RegistrationStateCompleted {
		if !record.deviceInternalID.Valid || record.deviceInternalID.Int64 <= 0 {
			return enrollment.Registration{}, ErrRegistrationEvidence
		}
	}
	value, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 registrationID,
		Scope:              scope,
		ProfileID:          profileID,
		MachineFingerprint: fingerprint,
		State:              state,
		NodeID:             nodeID,
		CreatedAt:          record.createdAt,
		ExpiresAt:          record.expiresAt,
	})
	if err != nil && state != enrollment.RegistrationStateCompleted {
		return enrollment.Registration{}, ErrRegistrationEvidence
	}
	return value, err
}

type registrationPrefix struct {
	internalID      int64
	realmInternalID int64
	poolInternalID  int64
	prefix          netip.Prefix
	family          int
	occupied        []netip.Addr
}

type registrationAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type registrationDeviceRecord struct {
	internalID        int64
	publicID          string
	profileInternalID int64
	hostname          string
	version           int64
	machineKey        []byte
	nodeKey           []byte
	// handover reports a browser resume by the member a suspended Device
	// is being handed over to (schema 125); the resume makes them its owner.
	handover bool
	// hostnameLocked keeps an administrator's rename across client logins;
	// workspaceOwned keeps a Workspace Device's never-expiring lifetime.
	hostnameLocked bool
	workspaceOwned bool
	expiresAt      time.Time
}

type registrationLockedState struct {
	command                  registration.Command
	resolution               registration.Resolution
	credential               registrationCredentialRecord
	profile                  registrationProfileRecord
	pending                  pendingRegistrationRecord
	device                   registrationDeviceRecord
	currentNetworkRevision   int64
	currentInventoryRevision int64
	audit                    registrationAuditHead
	hostnames                []node.Hostname
	prefixes                 []registrationPrefix
	activeLeaseFamilies      map[int]struct{}
}

func registrationBytes32(value []byte) ([32]byte, error) {
	if len(value) != 32 {
		return [32]byte{}, ErrRegistrationEvidence
	}
	var result [32]byte
	copy(result[:], value)
	if result == ([32]byte{}) {
		return [32]byte{}, ErrRegistrationEvidence
	}
	return result, nil
}

func registrationUseLimit(kind string, maximum sql.NullInt64) (enrollment.UseLimit, error) {
	switch kind {
	case "bounded":
		if !maximum.Valid {
			return enrollment.UseLimit{}, ErrRegistrationEvidence
		}
		limit, err := enrollment.NewBoundedUseLimit(maximum.Int64)
		if err != nil {
			return enrollment.UseLimit{}, ErrRegistrationEvidence
		}
		return limit, nil
	case "unlimited":
		if maximum.Valid {
			return enrollment.UseLimit{}, ErrRegistrationEvidence
		}
		return enrollment.NewUnlimitedUseLimit(), nil
	default:
		return enrollment.UseLimit{}, ErrRegistrationEvidence
	}
}

func registrationCredentialState(value string) (enrollment.CredentialState, error) {
	switch value {
	case "active":
		return enrollment.CredentialStateActive, nil
	case "revoked":
		return enrollment.CredentialStateRevoked, nil
	default:
		return enrollment.CredentialStateUnknown, ErrRegistrationEvidence
	}
}

func registrationProfileState(value string) (enrollment.ProfileState, error) {
	switch value {
	case "active":
		return enrollment.ProfileStateActive, nil
	case "suspended":
		return enrollment.ProfileStateSuspended, nil
	case "deleted":
		return enrollment.ProfileStateDeleted, nil
	default:
		return enrollment.ProfileStateUnknown, ErrRegistrationEvidence
	}
}

func registrationEphemeralMode(value string) (enrollment.EphemeralMode, error) {
	switch value {
	case "persistent":
		return enrollment.EphemeralModePersistent, nil
	case "ephemeral":
		return enrollment.EphemeralModeEphemeral, nil
	default:
		return enrollment.EphemeralModeUnknown, ErrRegistrationEvidence
	}
}

func registrationPendingState(value string) (enrollment.RegistrationState, error) {
	switch value {
	case "pending":
		return enrollment.RegistrationStatePending, nil
	case "authorized":
		return enrollment.RegistrationStateAuthorized, nil
	case "completed":
		return enrollment.RegistrationStateCompleted, nil
	case "rejected":
		return enrollment.RegistrationStateRejected, nil
	case "expired":
		return enrollment.RegistrationStateExpired, nil
	default:
		return enrollment.RegistrationStateUnknown, ErrRegistrationEvidence
	}
}

func registrationPrefixValue(value string, family int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || family != 4 && family != 6 ||
		prefix.Addr().Is4() != (family == 4) {
		return netip.Prefix{}, ErrRegistrationEvidence
	}
	return prefix, nil
}

func registrationAddressValue(value string, family int, prefix netip.Prefix) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4In6() || address.Is4() != (family == 4) ||
		!prefix.Contains(address) {
		return netip.Addr{}, ErrRegistrationEvidence
	}
	return address, nil
}

func registrationEvidenceError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRegistrationEvidence) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w", operation, ErrRegistrationEvidence)
}

func (locked registrationLockedState) profileInternalID() int64 {
	return locked.profile.internalID
}
