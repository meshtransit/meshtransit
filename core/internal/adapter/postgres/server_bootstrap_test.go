package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func validServerBootstrapOptions() ServerBootstrapOptions {
	password := []byte(strings.Repeat("Kq7x", 8))
	return ServerBootstrapOptions{
		Address: "db.example.test:5432", MaintenanceDatabase: "postgres", Admin: "doadmin",
		ConnectTimeout: time.Second, StatementTimeout: 30 * time.Second, Marker: "meshtransit:01995d00-0000-7000-8000-000000000001",
		Logins: []ServerBootstrapLogin{
			{Name: "mesh_migrator", Database: "meshtransit", Password: password},
			{Name: "mesh_control", Database: "meshtransit", Password: password, MemberOf: []string{"mesh_control_rights"},
				NotMemberOf: []string{"mesh_runtime"}},
			{Name: "mesh_observer", Database: "meshtransit"},
			{Name: "identity_runtime", Database: "identity", Password: password},
		},
		Databases: []ServerBootstrapDatabase{
			{Name: "meshtransit", Owner: "mesh_migrator"}, {Name: "identity", Owner: "identity_migrator"},
		},
		CoreDatabase: "meshtransit", Migrator: "mesh_migrator",
	}
}

func TestServerBootstrapOptionsValidate(t *testing.T) {
	t.Parallel()
	if err := validServerBootstrapOptions().validate(); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	for name, change := range map[string]func(*ServerBootstrapOptions){
		"quoted name":       func(o *ServerBootstrapOptions) { o.Logins[0].Name = `mesh"x` },
		"upper case":        func(o *ServerBootstrapOptions) { o.Admin = "DOADMIN" },
		"group with space":  func(o *ServerBootstrapOptions) { o.Logins[1].MemberOf = []string{"a b"} },
		"database name":     func(o *ServerBootstrapOptions) { o.Databases[0].Name = "mesh-transit" },
		"no migrator":       func(o *ServerBootstrapOptions) { o.Migrator = "mesh_absent" },
		"migrator no pass":  func(o *ServerBootstrapOptions) { o.Logins[0].Password = nil },
		"weak password":     func(o *ServerBootstrapOptions) { o.Logins[1].Password = []byte("short") },
		"quote in password": func(o *ServerBootstrapOptions) { o.Logins[1].Password = []byte(strings.Repeat("a'", 12)) },
		"no marker":         func(o *ServerBootstrapOptions) { o.Marker = "" },
		"quote in marker":   func(o *ServerBootstrapOptions) { o.Marker = "meshtransit:a'b" },
		"login database":    func(o *ServerBootstrapOptions) { o.Logins[3].Database = "" },
		"admin is ours":     func(o *ServerBootstrapOptions) { o.Admin = "mesh_migrator" },
		"core not created":  func(o *ServerBootstrapOptions) { o.Databases = o.Databases[1:] },
		"core owner":        func(o *ServerBootstrapOptions) { o.Databases[0].Owner = "mesh_control" },
		"no address":        func(o *ServerBootstrapOptions) { o.Address = "" },
		"no timeout":        func(o *ServerBootstrapOptions) { o.StatementTimeout = 0 },
		"timeout too short": func(o *ServerBootstrapOptions) { o.StatementTimeout = time.Millisecond },
	} {
		options := validServerBootstrapOptions()
		change(&options)
		if err := options.validate(); !errors.Is(err, ErrInvalidServerBootstrap) {
			t.Errorf("%s: validate() = %v", name, err)
		}
	}
}

// A wrong password means the Secret does not sign in; a pg_hba refusal
// comes before the password is checked and proves nothing; a refusal that
// only comes after authentication proves the password.
func TestAuthenticationOutcome(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err  error
		want authenticationResult
	}{
		{&pgconn.PgError{Code: "28P01"}, authenticationRefused},
		{&pgconn.PgError{Code: "28000"}, authenticationNotChecked},
		{fmt.Errorf("connect: %w", &pgconn.PgError{Code: "42501"}), authenticationPassed},
		{&pgconn.PgError{Code: "3D000"}, authenticationPassed},
		{&pgconn.PgError{Code: "53300"}, authenticationUnknown},
		{errors.New("dial tcp: refused"), authenticationUnknown},
	} {
		if got := authenticationOutcome(test.err); got != test.want {
			t.Errorf("authenticationOutcome(%v) = %d, want %d", test.err, got, test.want)
		}
	}
}
