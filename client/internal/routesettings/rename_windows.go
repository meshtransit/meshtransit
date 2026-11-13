package routesettings

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Readers open the settings without FILE_SHARE_DELETE (os.Open), so
// replacing them fails while one reads; the reads are short.
const (
	renameAttempts = 20
	renamePause    = 25 * time.Millisecond
)

// replaceFile renames from over to, again for a short while when a reader
// holds to open.
func replaceFile(from, to string) error {
	var err error
	for attempt := range renameAttempts {
		if attempt > 0 {
			time.Sleep(renamePause * time.Duration(attempt) / 4)
		}
		if err = os.Rename(from, to); err == nil || !sharingViolation(err) {
			return err
		}
	}
	return err
}

func sharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
