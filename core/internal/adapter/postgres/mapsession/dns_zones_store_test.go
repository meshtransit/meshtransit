package mapsession

import (
	"context"
	"errors"
	"slices"
	"testing"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/sharing"
)

func TestWithoutProtectedZones(t *testing.T) {
	t.Parallel()
	zones := []appmapsession.DNSZone{{Zone: 1, Domain: "corp.internal"}, {Zone: 2, Domain: "lab.lan"},
		{Zone: 3, Domain: "."}, {Zone: 4, Domain: "relay.lab.lan"}}
	names := []appmapsession.DNSName{{Zone: 1, FQDN: "git.corp.internal"}, {Zone: 2, FQDN: "nas.lab.lan"},
		{Zone: 4, FQDN: "x.relay.lab.lan"}}
	keptZones, keptNames := withoutProtectedZones(zones, names, []string{"relay2.corp.internal", "relay.lab.lan"})
	var domains []string
	for _, zone := range keptZones {
		domains = append(domains, zone.Domain)
	}
	// corp.internal holds relay2, relay.lab.lan is a protected name and its
	// parent lab.lan holds it; the root waits for D1b.
	if !slices.Equal(domains, []string{"."}) || len(keptNames) != 0 {
		t.Fatalf("zones %v, names %v", domains, keptNames)
	}
	if kept, _ := withoutProtectedZones(zones, names, nil); len(kept) != 4 {
		t.Fatalf("without protected names: %d zones", len(kept))
	}
}

// dnsNameTransaction answers the DNS name readers: schema 219's when
// shares is set, else schema 216's, with rows.
type dnsNameTransaction struct {
	*fakeTransaction
	shares bool
	rows   [][]any
	read   string
}

func (transaction *dnsNameTransaction) Query(ctx context.Context, query string, arguments ...any) (databaseRows,
	error) {
	switch query {
	case dnsShareNamesGrantedSQL:
		return &grantRows{granted: transaction.shares}, nil
	case loadNetworkDNSNamesSQL, loadNetworkDNSShareNamesSQL:
		transaction.read = query
		return &genericRows{rows: transaction.rows}, nil
	}
	return transaction.fakeTransaction.Query(ctx, query, arguments...)
}

// Maps read the names that point at a share from schema 219 (DNS design
// D3b), with their share and no other target; before it, from schema 216,
// which leaves them out.
func TestReadNetworkDNSNamesReadsShareNames(t *testing.T) {
	t.Parallel()
	const share = "01890f00-0000-7000-8000-00000000b001"
	want, err := sharing.ParseImportedResourceID(share)
	if err != nil {
		t.Fatal(err)
	}
	zones := []appmapsession.DNSZone{{Zone: 1, Domain: "corp.com"}}
	row := func(fqdn, kind, device, cname, share string, addresses ...string) []any {
		return []any{int64(1), fqdn, kind, int64(0), device, addresses, cname, share}
	}
	read := func(t *testing.T, shares bool, rows ...[]any) ([]appmapsession.DNSName, string, error) {
		t.Helper()
		transaction := &dnsNameTransaction{fakeTransaction: &fakeTransaction{}, shares: shares, rows: rows}
		names, err := readNetworkDNSNames(context.Background(), transaction, zones)
		return names, transaction.read, err
	}
	names, query, err := read(t, true, row("app.corp.com", "address", "", "", share),
		row("www.corp.com", "address", "", "", "", "192.0.2.80"))
	if err != nil || query != loadNetworkDNSShareNamesSQL || len(names) != 2 ||
		names[0].Share != want || names[0].NodeID.IsValid() ||
		len(names[0].Addresses) != 0 || names[1].Share.IsValid() || len(names[1].Addresses) != 1 {
		t.Fatalf("names = %+v, query = %q, error = %v", names, query, err)
	}
	if _, query, err := read(t, false); err != nil || query != loadNetworkDNSNamesSQL {
		t.Fatalf("before schema 219: query = %q, error = %v", query, err)
	}
	for name, broken := range map[string][]any{
		"a share and a Device":    row("app.corp.com", "address", testPeerNodeID, "", share),
		"a share and addresses":   row("app.corp.com", "address", "", "", share, "192.0.2.80"),
		"a share and a CNAME":     row("app.corp.com", "cname", "", "www.corp.com", share),
		"a share that is no UUID": row("app.corp.com", "address", "", "", "app"),
	} {
		if _, _, err := read(t, true, broken); !errors.Is(err, ErrSnapshotEvidence) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
