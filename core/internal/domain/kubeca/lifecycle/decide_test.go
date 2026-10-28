package lifecycle

import (
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

const testName = "prod.kube.123456789012.210987654321.mesh.test"

var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

func testID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// stored is a live CA of the test cluster: created is an offset from
// testNow, left its remaining life.
func stored(t *testing.T, kind kubeca.Kind, state kubeca.State, issuer publicid.ID, name string,
	created, left time.Duration,
) kubeca.StoredCA {
	t.Helper()
	ca := kubeca.StoredCA{
		ID: testID(t), Version: 1, Kind: kind, IssuerID: issuer, State: state, Reason: kubeca.ReasonScheduled,
		ClusterDNSName: name, CreatedAt: testNow.Add(created), NotBefore: testNow.Add(created),
		NotAfter: testNow.Add(left),
	}
	switch state {
	case kubeca.StateActive:
		ca.ActivatedAt, ca.SealedKey = ca.CreatedAt, []byte{1}
	case kubeca.StateNext:
		ca.SealedKey = []byte{1}
	case kubeca.StateRetiring:
		ca.ActivatedAt, ca.RetiringAt = ca.CreatedAt, testNow.Add(created/2)
	}
	return ca
}

func root(t *testing.T, state kubeca.State, name string, created, left time.Duration) kubeca.StoredCA {
	t.Helper()
	return stored(t, kubeca.KindRoot, state, publicid.ID{}, name, created, left)
}

func intermediate(t *testing.T, state kubeca.State, issuer kubeca.StoredCA, created, left time.Duration) kubeca.StoredCA {
	t.Helper()
	return stored(t, kubeca.KindIntermediate, state, issuer.ID, issuer.ClusterDNSName, created, left)
}

func retiringSince(ca kubeca.StoredCA, ago time.Duration) kubeca.StoredCA {
	ca.RetiringAt = testNow.Add(-ago)
	return ca
}

func short(ca kubeca.StoredCA) string { return ca.ID.String()[:8] }

// describe renders a decision as one line per action, in order, then the
// schedules.
func describe(decision Decision) string {
	var lines []string
	for _, action := range decision.Actions {
		switch {
		case action.Create != nil:
			line := "create " + action.Create.Kind.String() + " " + string(action.Create.State) + " " +
				string(action.Create.Reason)
			switch {
			case action.Create.IssuerNew:
				line += " under new root"
			case action.Create.Issuer.IsValid():
				line += " under " + action.Create.Issuer.String()[:8]
			}
			lines = append(lines, line)
		case action.Move != nil:
			lines = append(lines, "move "+action.Move.CA.String()[:8]+" "+string(action.Move.To)+" "+
				string(action.Move.Reason))
		}
	}
	for _, schedule := range decision.Schedules {
		switch {
		case schedule.Done:
			lines = append(lines, "done")
		case schedule.Failed:
			lines = append(lines, "failed in "+schedule.At.Sub(testNow).String())
		default:
			lines = append(lines, "next in "+schedule.At.Sub(testNow).String())
		}
	}
	return strings.Join(lines, "; ")
}

func TestDecide(t *testing.T) {
	t.Parallel()
	year := 365 * day
	activeRoot := root(t, kubeca.StateActive, testName, -100*day, 9*year)
	activeInter := intermediate(t, kubeca.StateActive, activeRoot, -5*day, 25*day)
	endingInter := intermediate(t, kubeca.StateActive, activeRoot, -22*day, 8*day)
	expiredInter := intermediate(t, kubeca.StateActive, activeRoot, -31*day, -time.Hour)
	oldInter := retiringSince(intermediate(t, kubeca.StateRetiring, activeRoot, -40*day, 20*day), 26*time.Hour)
	recentInter := retiringSince(intermediate(t, kubeca.StateRetiring, activeRoot, -40*day, 20*day), 2*time.Hour)
	endingRoot := root(t, kubeca.StateActive, testName, -9*year, 300*day)
	underEnding := intermediate(t, kubeca.StateActive, endingRoot, -5*day, 25*day)
	freshNext := root(t, kubeca.StateNext, testName, -10*day, 10*year)
	publishedNext := root(t, kubeca.StateNext, testName, -91*day, 10*year)
	oldRoot := retiringSince(root(t, kubeca.StateRetiring, testName, -9*year, 300*day), 26*time.Hour)
	underOld := retiringSince(intermediate(t, kubeca.StateRetiring, oldRoot, -10*day, 20*day), 26*time.Hour)
	strayInter := intermediate(t, kubeca.StateActive, oldRoot, -5*day, 25*day)
	renamedRoot := root(t, kubeca.StateActive, "prod.kube.old.example", -100*day, 9*year)
	underRenamed := intermediate(t, kubeca.StateActive, renamedRoot, -5*day, 25*day)
	wrongNext := root(t, kubeca.StateNext, "prod.kube.old.example", -10*day, 10*year)
	dyingRoot := root(t, kubeca.StateActive, testName, -10*year, 30*time.Minute)
	dyingInter := intermediate(t, kubeca.StateActive, dyingRoot, -day, 30*time.Minute)
	dyingRetiring := retiringSince(intermediate(t, kubeca.StateRetiring, dyingRoot, -3*day, 30*time.Minute),
		2*time.Hour)

	for _, test := range []struct {
		name   string
		active bool
		cas    []kubeca.StoredCA
		dns    string
		want   string
	}{
		{
			name: "a new cluster gets its root and intermediate", active: true, dns: testName,
			want: "create root active initial; create intermediate active initial under new root; next in 24h0m0s",
		},
		{
			name: "a cluster mid-life waits a day", active: true, dns: testName,
			cas: []kubeca.StoredCA{activeRoot, activeInter}, want: "next in 24h0m0s",
		},
		{
			name: "an intermediate within 10 days hands over", active: true, dns: testName,
			cas: []kubeca.StoredCA{activeRoot, endingInter},
			want: "move " + short(endingInter) + " retiring scheduled; create intermediate active scheduled under " +
				short(activeRoot) + "; next in 24h0m0s",
		},
		{
			name: "an expired intermediate retires outright", active: true, dns: testName,
			cas: []kubeca.StoredCA{activeRoot, expiredInter},
			want: "move " + short(expiredInter) + " retired expired; create intermediate active scheduled under " +
				short(activeRoot) + "; next in 24h0m0s",
		},
		{
			name: "a retiring intermediate retires after 25 hours", active: true, dns: testName,
			cas:  []kubeca.StoredCA{activeRoot, activeInter, oldInter, recentInter},
			want: "move " + short(oldInter) + " retired scheduled; next in 23h0m0s",
		},
		{
			name: "a root without intermediate gets one", active: true, dns: testName,
			cas:  []kubeca.StoredCA{activeRoot},
			want: "create intermediate active scheduled under " + short(activeRoot) + "; next in 24h0m0s",
		},
		{
			name: "an intermediate of another root hands over", active: true, dns: testName,
			cas: []kubeca.StoredCA{activeRoot, strayInter},
			want: "move " + short(strayInter) + " retiring scheduled; create intermediate active scheduled under " +
				short(activeRoot) + "; next in 24h0m0s",
		},
		{
			name: "a root within a year publishes its successor", active: true, dns: testName,
			cas:  []kubeca.StoredCA{endingRoot, underEnding},
			want: "create root next scheduled; next in 24h0m0s",
		},
		{
			name: "a successor root published 90 days takes over", active: true, dns: testName,
			cas: []kubeca.StoredCA{endingRoot, underEnding, publishedNext, oldRoot, underOld},
			want: "move " + short(underOld) + " retired scheduled; move " + short(oldRoot) + " retired scheduled; move " +
				short(underEnding) + " retiring scheduled; move " + short(endingRoot) + " retiring scheduled; move " +
				short(publishedNext) + " active scheduled; create intermediate active scheduled under " +
				short(publishedNext) + "; next in 24h0m0s",
		},
		{
			name: "a successor root published under 90 days waits", active: true, dns: testName,
			cas: []kubeca.StoredCA{endingRoot, underEnding, freshNext}, want: "next in 24h0m0s",
		},
		{
			name: "a root under another name is left alone", active: true, dns: testName,
			cas: []kubeca.StoredCA{renamedRoot, underRenamed, wrongNext}, want: "failed in 1h0m0s",
		},
		{
			name: "a successor root under another name is left alone", active: true, dns: testName,
			cas: []kubeca.StoredCA{activeRoot, activeInter, wrongNext}, want: "failed in 1h0m0s",
		},
		{
			name: "an ending root retires with its retiring intermediates", active: true, dns: testName,
			cas: []kubeca.StoredCA{dyingRoot, dyingInter, dyingRetiring, freshNext},
			want: "move " + short(dyingInter) + " retired expired; move " + short(dyingRetiring) +
				" retired expired; move " + short(dyingRoot) + " retired expired; move " + short(freshNext) +
				" active scheduled; create intermediate active scheduled under " + short(freshNext) + "; next in 24h0m0s",
		},
		{
			name: "a cluster that cannot be named is retried", active: true,
			cas: []kubeca.StoredCA{activeRoot, activeInter}, want: "failed in 1h0m0s",
		},
		{
			name: "a deleted cluster retires intermediates, then roots, and ends",
			cas:  []kubeca.StoredCA{activeRoot, activeInter, freshNext, recentInter},
			want: "move " + short(activeInter) + " retired cluster_deleted; move " + short(recentInter) +
				" retired cluster_deleted; move " + short(activeRoot) + " retired cluster_deleted; move " +
				short(freshNext) + " retired cluster_deleted; done",
		},
		{name: "a deleted cluster without CAs ends", want: "done"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cluster := kubeca.Cluster{
				ID: testID(t), Name: "prod", Active: test.active, NextActionAt: testNow,
				CAs: test.cas,
			}
			names := map[publicid.ID]string{}
			if test.dns != "" {
				names[cluster.ID] = test.dns
			}
			decision := Decide(kubeca.Network{Now: testNow, Clusters: []kubeca.Cluster{cluster}}, names,
				DefaultPolicy())
			if got := describe(decision); got != test.want {
				t.Errorf("Decide() =\n  %s\nwant\n  %s", got, test.want)
			}
			for _, action := range decision.Actions {
				if action.Cluster != cluster.ID || (action.Create != nil) == (action.Move != nil) {
					t.Errorf("action %+v", action)
				}
				if action.Create != nil && action.Create.ClusterDNSName != test.dns {
					t.Errorf("create names %q", action.Create.ClusterDNSName)
				}
			}
		})
	}
}

func TestDecideCoversEveryCluster(t *testing.T) {
	t.Parallel()
	first, second := kubeca.Cluster{ID: testID(t), Active: true}, kubeca.Cluster{ID: testID(t), Active: true}
	decision := Decide(kubeca.Network{Now: testNow, Clusters: []kubeca.Cluster{first, second}},
		map[publicid.ID]string{first.ID: testName, second.ID: testName}, DefaultPolicy())
	if len(decision.Actions) != 4 || len(decision.Schedules) != 2 ||
		decision.Schedules[0].Cluster != first.ID || decision.Schedules[1].Cluster != second.ID {
		t.Fatalf("Decide() = %+v", decision)
	}
}

func TestPolicyBounds(t *testing.T) {
	t.Parallel()
	if !DefaultPolicy().Valid() {
		t.Fatal("the default policy is invalid")
	}
	for name, change := range map[string]func(*Policy){
		"rotates a root as soon as it is made":   func(p *Policy) { p.RootRotateBefore = p.RootLifetime },
		"publishes a root after it would rotate": func(p *Policy) { p.RootPublishFor = p.RootRotateBefore },
		"hands over an intermediate too late": func(p *Policy) {
			p.IntermediateRotateBefore = kubeca.ReplicaLifetime
		},
		"retires before certificates end": func(p *Policy) { p.RetireAfter = kubeca.ReplicaLifetime },
		"jitters past the bounds":         func(p *Policy) { p.IntermediateJitter = p.IntermediateLifetime },
	} {
		broken := DefaultPolicy()
		change(&broken)
		if broken.Valid() {
			t.Errorf("%s: valid", name)
		}
	}
}

// Only an operator's request renames a cluster: its roots under another
// name are replaced at once; other clusters of the Network are not.
func TestDecideRename(t *testing.T) {
	t.Parallel()
	year := 365 * day
	renamedRoot := root(t, kubeca.StateActive, "prod.kube.old.example", -100*day, 9*year)
	underRenamed := intermediate(t, kubeca.StateActive, renamedRoot, -5*day, 25*day)
	wrongNext := root(t, kubeca.StateNext, "prod.kube.old.example", -10*day, 10*year)
	other := root(t, kubeca.StateActive, "other.kube.old.example", -100*day, 9*year)
	cluster := kubeca.Cluster{
		ID: testID(t), Name: "prod", Active: true,
		CAs: []kubeca.StoredCA{renamedRoot, underRenamed, wrongNext},
	}
	untouched := kubeca.Cluster{ID: testID(t), Name: "other", Active: true, CAs: []kubeca.StoredCA{other}}
	read := kubeca.Network{Now: testNow, Clusters: []kubeca.Cluster{cluster, untouched}}
	names := map[publicid.ID]string{cluster.ID: testName, untouched.ID: "other.kube.new.example"}
	decision := DecideRename(read, names, DefaultPolicy(), cluster.ID)
	want := "move " + short(wrongNext) + " retired name_changed; move " + short(underRenamed) +
		" retiring name_changed; move " + short(renamedRoot) + " retiring name_changed; " +
		"create root active name_changed; create intermediate active name_changed under new root; " +
		"next in 24h0m0s; failed in 1h0m0s"
	if got := describe(decision); got != want {
		t.Fatalf("DecideRename() =\n  %s\nwant\n  %s", got, want)
	}
	if len(decision.Misnamed) != 1 || decision.Misnamed[0] != untouched.ID {
		t.Fatalf("misnamed %v", decision.Misnamed)
	}
	if plain := Decide(read, names, DefaultPolicy()); len(plain.Actions) != 0 || len(plain.Misnamed) != 2 {
		t.Fatalf("Decide() renamed: %s", describe(plain))
	}
}
