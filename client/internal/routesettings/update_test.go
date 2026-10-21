//go:build linux || darwin

package routesettings

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// loadAnyOwner reads the settings as Load does, without Load's owner check:
// the tests do not run as root.
func loadAnyOwner(path string) (Settings, error) {
	encoded, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Decode(encoded)
}

// The writers count up the consumer limit: with every update a step against
// the others, none is lost.
func TestUpdateLosesNoWriterAgainstAnother(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	const writers, steps = 4, 25
	var group sync.WaitGroup
	for range writers {
		group.Go(func() {
			for range steps {
				_, err := update(path, loadAnyOwner, Save, func(current Settings, err error) (Settings, error) {
					current.ExitMaxConsumers++
					return current, err
				})
				if err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
	settings, err := loadAnyOwner(path)
	if err != nil || settings.ExitMaxConsumers != writers*steps {
		t.Fatalf("consumer limit = %d, %v; want %d", settings.ExitMaxConsumers, err, writers*steps)
	}
}

func TestUpdateReturnsTheSettingsReadBackAndKeepsAFailedChangeOut(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	got, err := update(path, loadAnyOwner, Save, func(current Settings, _ error) (Settings, error) {
		current.OperatorsOff = true
		return current, nil
	})
	if err != nil || !got.OperatorsOff {
		t.Fatalf("update() = %+v, %v", got, err)
	}
	refused := errors.New("refused")
	if _, err := update(path, loadAnyOwner, Save, func(Settings, error) (Settings, error) {
		return Settings{}, refused
	}); !errors.Is(err, refused) {
		t.Fatalf("update() = %v, want the change's error", err)
	}
	if settings, err := loadAnyOwner(path); err != nil || !settings.OperatorsOff {
		t.Fatalf("a refused change wrote the file: %+v, %v", settings, err)
	}
}
