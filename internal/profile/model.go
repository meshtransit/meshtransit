// Package profile owns the single-active-profile invariant for MeshTransit networks.
package profile

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	stateVersion   = 1
	maxNameRunes   = 64
	profileIDBytes = 16
)

var (
	// ErrInvalid indicates that user-supplied profile data failed validation.
	ErrInvalid = errors.New("profile: invalid")
	// ErrNotFound indicates that a requested profile does not exist.
	ErrNotFound = errors.New("profile: not found")
	// ErrDuplicate indicates that a profile name already exists.
	ErrDuplicate = errors.New("profile: duplicate name")
)

// Profile identifies one control-plane account and its isolated network view.
// Network identifiers are deliberately absent: the control plane derives them
// from the authenticated registration or session credential.
type Profile struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ControlURL string    `json:"control_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Snapshot is the complete persisted profile state.
type Snapshot struct {
	Version         int       `json:"version"`
	ActiveProfileID string    `json:"active_profile_id"`
	Profiles        []Profile `json:"profiles"`
}

// CreateInput contains user-controlled fields accepted for a new profile.
type CreateInput struct {
	Name       string
	ControlURL string
}

func normalizeInput(input CreateInput) (CreateInput, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return CreateInput{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if !utf8.ValidString(name) {
		return CreateInput{}, fmt.Errorf("%w: name must be valid utf-8", ErrInvalid)
	}
	if utf8.RuneCountInString(name) > maxNameRunes {
		return CreateInput{}, fmt.Errorf("%w: name exceeds %d characters", ErrInvalid, maxNameRunes)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return CreateInput{}, fmt.Errorf("%w: name cannot contain control characters", ErrInvalid)
		}
	}

	controlURL, err := normalizeControlURL(input.ControlURL)
	if err != nil {
		return CreateInput{}, err
	}

	return CreateInput{
		Name:       name,
		ControlURL: controlURL,
	}, nil
}

func normalizeControlURL(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("%w: parsing control url: %w", ErrInvalid, err)
	}
	if parsed.Opaque != "" || !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("%w: control url must use https", ErrInvalid)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("%w: control url must include a host", ErrInvalid)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: control url cannot contain user information", ErrInvalid)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", fmt.Errorf("%w: control url contains unsupported components", ErrInvalid)
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("%w: control url must use port 443", ErrInvalid)
	}

	parsed.Scheme = "https"
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path != "" {
		parsed.Path = path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	}
	if parsed.Path != "/" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}

	return parsed.String(), nil
}

func newSnapshot() Snapshot {
	return Snapshot{
		Version:  stateVersion,
		Profiles: []Profile{},
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	cloned := snapshot
	cloned.Profiles = append([]Profile{}, snapshot.Profiles...)

	return cloned
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Version != stateVersion {
		return fmt.Errorf("unsupported state version %d", snapshot.Version)
	}
	if snapshot.Profiles == nil {
		return errors.New("profiles must be an array")
	}

	ids := make(map[string]struct{}, len(snapshot.Profiles))
	for index, item := range snapshot.Profiles {
		if !isProfileID(item.ID) {
			return fmt.Errorf("invalid profile id %q", item.ID)
		}
		normalized, err := normalizeInput(CreateInput{
			Name:       item.Name,
			ControlURL: item.ControlURL,
		})
		if err != nil {
			return fmt.Errorf("validating profile %q: %w", item.ID, err)
		}
		if normalized.Name != item.Name || normalized.ControlURL != item.ControlURL {
			return fmt.Errorf("profile %q contains non-canonical fields", item.ID)
		}
		if item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
			return fmt.Errorf("profile %q contains a zero timestamp", item.ID)
		}
		if item.UpdatedAt.Before(item.CreatedAt) {
			return fmt.Errorf("profile %q was updated before it was created", item.ID)
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate profile id %q", item.ID)
		}
		ids[item.ID] = struct{}{}

		for _, previous := range snapshot.Profiles[:index] {
			if strings.EqualFold(previous.Name, item.Name) {
				return fmt.Errorf("duplicate profile name %q", item.Name)
			}
		}
	}

	if snapshot.ActiveProfileID == "" {
		if len(snapshot.Profiles) > 0 {
			return errors.New("non-empty profile state must have one active profile")
		}

		return nil
	}
	if _, exists := ids[snapshot.ActiveProfileID]; !exists {
		return fmt.Errorf("active profile %q does not exist", snapshot.ActiveProfileID)
	}

	return nil
}

func isProfileID(id string) bool {
	if len(id) != profileIDBytes*2 {
		return false
	}
	for _, r := range id {
		isDigit := r >= '0' && r <= '9'
		isLowerHex := r >= 'a' && r <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}

	return true
}
