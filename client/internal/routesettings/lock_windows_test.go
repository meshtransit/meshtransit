package routesettings

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// plainLoad and plainSave read and write the settings without the private
// directory checks, which a test's temporary directory does not pass.
func plainLoad(path string) (Settings, error) {
	encoded, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Decode(encoded)
}

func plainSave(path string, settings Settings) error {
	encoded, err := Encode(settings)
	if err != nil {
		return err
	}
	temporary := path + ".tmp" + fmt.Sprint(time.Now().UnixNano())
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return replaceFile(temporary, path)
}

// Writers that each add one subnet under the lock lose none of them.
func TestLockedUpdatesLoseNothing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	const writers = 24
	var group sync.WaitGroup
	errs := make(chan error, writers)
	for index := range writers {
		group.Go(func() {
			octet := byte(index) //nolint:gosec // index < writers
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, octet, 0, 0}), 16)
			_, err := lockedUpdate(path, plainLoad, plainSave, func(current Settings, loadErr error) (Settings, error) {
				if loadErr != nil {
					return current, loadErr
				}
				current.AdvertiseRoutes = append(current.AdvertiseRoutes, prefix)
				return current, nil
			})
			errs <- err
		})
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	settings, err := plainLoad(path)
	if err != nil || len(settings.AdvertiseRoutes) != writers {
		t.Fatalf("after %d locked updates: %d routes, %v", writers, len(settings.AdvertiseRoutes), err)
	}
}

// A reader holding the file open briefly does not fail a change.
func TestReplaceWaitsForAReader(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := plainSave(path, Settings{}); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = reader.Close()
	}()
	if err := plainSave(path, Settings{AcceptRoutes: true}); err != nil {
		t.Fatalf("replacing while read: %v", err)
	}
	if settings, err := plainLoad(path); err != nil || !settings.AcceptRoutes {
		t.Fatalf("after the replace: %+v, %v", settings, err)
	}
}

// UpdateExisting creates nothing: a missing directory stays missing, and
// a directory others may open is refused.
func TestUpdateExistingCreatesNothing(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "settings")
	_, err := UpdateExisting(filepath.Join(missing, "routes.json"), func(current Settings, _ error) (Settings, error) {
		return current, nil
	})
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("missing directory: %v, want ErrUnsafeFile", err)
	}
	if _, statErr := os.Lstat(missing); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("UpdateExisting created %s: %v", missing, statErr)
	}
	open := t.TempDir()
	if _, err := UpdateExisting(filepath.Join(open, "routes.json"), func(current Settings, _ error) (Settings, error) {
		return current, nil
	}); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("a user's directory: %v, want ErrUnsafeFile", err)
	}
	if _, statErr := os.Lstat(filepath.Join(open, "routes.json.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("UpdateExisting locked in a user's directory: %v", statErr)
	}
}
