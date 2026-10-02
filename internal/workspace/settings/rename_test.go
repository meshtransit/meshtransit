package settings_test

import (
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
	"testing"
)

func TestWorkspaceName(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{"Default", true}, {"Development Mesh", true}, {"Nhóm kỹ thuật", true},
		{"", false}, {" Default", false}, {"Default ", false}, {"two\nlines", false}, {string([]byte{255}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if settings.ValidName(test.name) != test.valid {
				t.Fatal("incorrect name validation")
			}
		})
	}
}
