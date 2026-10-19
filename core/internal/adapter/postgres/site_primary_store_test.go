package postgres

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/site/election"
)

const (
	electionTestSite    = "01890f00-0000-7000-8000-000000000410"
	electionTestLater   = "01890f00-0000-7000-8000-000000000411"
	electionTestFirst   = "01890f00-0000-7000-8000-000000000421"
	electionTestSecond  = "01890f00-0000-7000-8000-000000000422"
	electionTestChange  = "01890f00-0000-7000-8000-000000000430"
	electionTestNetwork = "01890f00-0000-7000-8000-000000000201"
	electionTestSpace   = "01890f00-0000-7000-8000-000000000101"
)

func electionSite(id, routers string) string {
	return `{"site_id":"` + id + `","workspace_id":"` + electionTestSpace + `","network_id":"` + electionTestNetwork +
		`","failback":true,"primary_device_id":"` + electionTestSecond + `","generation":3,"routers":[` + routers + `]}`
}

func electionRouter(id string, priority, state string) string {
	return `{"device_id":"` + id + `","priority":` + priority + `,"state":"` + state +
		`","live":true,"workspace_owned":true,"covers":false}`
}

func TestDecodeSiteElectionPage(t *testing.T) {
	t.Parallel()
	two := electionRouter(electionTestFirst, "10", "active") + "," + electionRouter(electionTestSecond, "20", "draining")
	for _, test := range []struct {
		name, encoded string
		after         string
		limit         int
		wantErr       bool
		wantSites     int
	}{
		{name: "empty", encoded: `{"items":[],"done":true}`, limit: 2},
		{name: "two Sites in order", limit: 2, wantSites: 2,
			encoded: `{"items":[` + electionSite(electionTestSite, two) + `,` + electionSite(electionTestLater, two) + `],"done":false}`},
		{name: "after the cursor", limit: 2, after: electionTestSite, wantErr: true,
			encoded: `{"items":[` + electionSite(electionTestSite, two) + `],"done":true}`},
		{name: "Sites out of order", limit: 2, wantErr: true,
			encoded: `{"items":[` + electionSite(electionTestLater, two) + `,` + electionSite(electionTestSite, two) + `],"done":true}`},
		{name: "a short page that is not done", limit: 2, wantErr: true,
			encoded: `{"items":[` + electionSite(electionTestSite, two) + `],"done":false}`},
		{name: "routers out of priority order", limit: 2, wantErr: true, encoded: `{"items":[` + electionSite(electionTestSite,
			electionRouter(electionTestFirst, "20", "active")+","+electionRouter(electionTestSecond, "10", "active")) + `],"done":true}`},
		{name: "a repeated router", limit: 2, wantErr: true, encoded: `{"items":[` + electionSite(electionTestSite,
			electionRouter(electionTestFirst, "10", "active")+","+electionRouter(electionTestFirst, "10", "active")) + `],"done":true}`},
		{name: "an unknown router state", limit: 2, wantErr: true, encoded: `{"items":[` + electionSite(electionTestSite,
			electionRouter(electionTestFirst, "10", "melted")) + `],"done":true}`},
		{name: "no routers", limit: 2, wantErr: true, encoded: `{"items":[` + electionSite(electionTestSite, "") + `],"done":true}`},
		{name: "an extra key", limit: 2, wantErr: true,
			encoded: `{"items":[` + strings.Replace(electionSite(electionTestSite, two), `"failback"`, `"x":1,"failback"`, 1) + `],"done":true}`},
		{name: "trailing value", limit: 2, wantErr: true, encoded: `{"items":[],"done":true}{}`},
	} {
		var after site.ID
		if test.after != "" {
			after, _ = site.ParseID(test.after)
		}
		page, err := decodeSiteElectionPage([]byte(test.encoded), after, test.limit)
		if (err != nil) != test.wantErr || test.wantErr && !errors.Is(err, ErrSitePrimary) {
			t.Errorf("%s: error = %v, wantErr %v", test.name, err, test.wantErr)
			continue
		}
		if test.wantErr || len(page.Sites) != test.wantSites {
			if !test.wantErr {
				t.Errorf("%s: page = %+v", test.name, page)
			}
			continue
		}
		if test.wantSites > 0 {
			facts := page.Sites[0]
			second, _ := node.ParseID(electionTestSecond)
			if facts.Generation != 3 || facts.Primary != second || !facts.Failback || len(facts.Routers) != 2 ||
				facts.Routers[0].Draining || !facts.Routers[1].Draining || facts.Routers[0].Covers {
				t.Errorf("%s: Site = %+v", test.name, facts)
			}
		}
	}
}

func TestDecodeSitePrimaryProof(t *testing.T) {
	t.Parallel()
	siteID, _ := site.ParseID(electionTestSite)
	change, _ := publicid.Parse(electionTestChange)
	decision := election.Decision{Site: siteID, ExpectedGeneration: 2, Reason: election.ReasonFailover}
	event := `{"workspace_id":"` + electionTestSpace + `","network_id":"` + electionTestNetwork +
		`","stream_id":4,"sequence":9,"previous_hash":"` + strings.Repeat("ab", 32) +
		`","network_revision":12,"audit_payload":"{}","outbox_payload":"{}"}`
	changed := func(generation string) string {
		return `{"changed":true,"transaction_id":"77","change_id":"` + electionTestChange + `","site_id":"` +
			electionTestSite + `","generation":` + generation + `,"aggregate_version":3,"event":` + event + `}`
	}
	for name, test := range map[string]struct {
		encoded     string
		wantErr     bool
		wantChanged bool
	}{
		"unchanged":               {encoded: `{"changed":false}`},
		"one generation on":       {encoded: changed("3"), wantChanged: true},
		"another generation":      {encoded: changed("4"), wantErr: true},
		"unchanged with evidence": {encoded: `{"changed":false,"event":` + event + `}`, wantErr: true},
		"another change":          {encoded: strings.Replace(changed("3"), electionTestChange, electionTestLater, 1), wantErr: true},
		"no event":                {encoded: strings.Replace(changed("3"), `,"event":`+event, "", 1), wantErr: true},
		"an unknown key":          {encoded: `{"changed":false,"blocked":true}`, wantErr: true},
	} {
		proof, err := decodeSitePrimaryProof([]byte(test.encoded), decision, change)
		if (err != nil) != test.wantErr || (err == nil && proof.Changed != test.wantChanged) {
			t.Errorf("%s: proof %+v, error %v", name, proof, err)
		}
		if test.wantChanged && err == nil {
			hashed, err := hashSitePrimaryEvent(proof, change, change, change)
			if err != nil || !strings.Contains(string(hashed), `"event_hash":"`) {
				t.Errorf("%s: hashed %s, error %v", name, hashed, err)
			}
		}
	}
}
