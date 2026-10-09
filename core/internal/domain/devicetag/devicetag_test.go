package devicetag_test

import (
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/devicetag"
	"github.com/meshtransit/meshtransit/core/internal/domain/identitygroup"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

func TestTagNames(t *testing.T) {
	t.Parallel()
	for name, valid := range map[string]bool{
		"prod-db": true, "k8s": true, "a": true, strings.Repeat("a", 48): true,
		"": false, "-db": false, "db-": false, "Prod": false, "prod_db": false, "prod db": false,
		strings.Repeat("a", 49): false, "tag:prod": false,
	} {
		if got := devicetag.ValidName(name); got != valid {
			t.Errorf("ValidName(%q) = %t, want %t", name, got, valid)
		}
	}
}

func TestDefinitionOwners(t *testing.T) {
	t.Parallel()
	group, _ := publicid.New()
	other, _ := publicid.New()
	base := devicetag.Definition{Name: "prod-db"}
	for _, test := range []struct {
		name   string
		groups []identitygroup.ID
		roles  []string
		valid  bool
	}{
		{name: "no owners", valid: true},
		{name: "group and role", groups: []identitygroup.ID{identitygroup.ID(group)}, roles: []string{"admin"}, valid: true},
		{name: "duplicate group", groups: []identitygroup.ID{identitygroup.ID(group), identitygroup.ID(group)}},
		{name: "duplicate role", roles: []string{"admin", "admin"}},
		{name: "unknown role", roles: []string{"owner"}},
		{name: "invalid group", groups: []identitygroup.ID{{}}},
	} {
		definition := base
		definition.OwnerGroups, definition.OwnerRoles = test.groups, test.roles
		if got := definition.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid() = %t, want %t", test.name, got, test.valid)
		}
	}
	canonical := devicetag.Definition{
		Name: "x", OwnerGroups: []identitygroup.ID{identitygroup.ID(other), identitygroup.ID(group)},
		OwnerRoles: []string{"network_admin", "admin"},
	}.Canonical()
	if canonical.OwnerRoles[0] != "admin" || canonical.OwnerGroups[0].String() > canonical.OwnerGroups[1].String() {
		t.Fatalf("Canonical() = %+v", canonical)
	}
}
