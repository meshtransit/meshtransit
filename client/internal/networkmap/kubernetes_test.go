package networkmap

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func tagID(index int) string { return fmt.Sprintf("01890f00-0000-7000-8000-%012d", index) }

// tagsOwner is the owner reference of a Device with count tags.
func tagsOwner(count int) string {
	ids := make([]string, count)
	for index := range ids {
		ids[index] = tagID(index)
	}
	return "tags:" + strings.Join(ids, ",")
}

// A peer's Kubernetes access holds one to 64 sorted groups, each with a
// deadline, and only on a peer of the Network; a group past its deadline is
// honoured no more.
func TestKubernetesAccessIsValidatedAndExpires(t *testing.T) {
	t.Parallel()
	now := time.Now()
	access := func(grants ...KubernetesGrant) *KubernetesAccess {
		return &KubernetesAccess{Grants: grants, OwnerRef: tagID(11)}
	}
	snapshot := validSnapshot()
	snapshot.Peers[0].Kubernetes = access(KubernetesGrant{"edit", now.Add(-time.Minute)},
		KubernetesGrant{"view", now.Add(time.Hour)})
	validated, err := ValidateAndClone(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Peers[0].Kubernetes.Grants[1].Group = "admin"
	got := validated.Peers[0].Kubernetes
	if !slices.Equal(got.GroupsAt(now), []string{"view"}) || got.OwnerRef != tagID(11) {
		t.Fatalf("validated access = %+v, groups now %v", got, got.GroupsAt(now))
	}
	if (*KubernetesAccess)(nil).GroupsAt(now) != nil {
		t.Fatal("no access holds groups")
	}
	for _, owner := range []string{"01890f00-0000-7000-8000-000000000011", tagsOwner(1), tagsOwner(7), tagsOwner(256)} {
		tagged := validSnapshot()
		tagged.Peers[0].Kubernetes = &KubernetesAccess{
			Grants:   []KubernetesGrant{{"view", now.Add(time.Hour)}},
			OwnerRef: owner,
		}
		if _, err := ValidateAndClone(tagged, now); err != nil {
			t.Fatalf("owner of %d bytes: %v", len(owner), err)
		}
	}
	workspace := validSnapshot()
	workspace.Peers[0].Kubernetes = &KubernetesAccess{Grants: []KubernetesGrant{{"view", now.Add(time.Hour)}}}
	if _, err := ValidateAndClone(workspace, now); err != nil {
		t.Fatalf("a Device of the Workspace: %v", err)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"self":        func(s *Snapshot) { s.Self.Kubernetes = access(KubernetesGrant{"view", now.Add(time.Hour)}) },
		"no grant":    func(s *Snapshot) { s.Peers[0].Kubernetes = access() },
		"no deadline": func(s *Snapshot) { s.Peers[0].Kubernetes = access(KubernetesGrant{Group: "view"}) },
		"unsorted": func(s *Snapshot) {
			s.Peers[0].Kubernetes = access(KubernetesGrant{"view", now}, KubernetesGrant{"edit", now})
		},
		"bad group": func(s *Snapshot) { s.Peers[0].Kubernetes = access(KubernetesGrant{"View", now}) },
		"system":    func(s *Snapshot) { s.Peers[0].Kubernetes = access(KubernetesGrant{"system:masters", now}) },
		"twice": func(s *Snapshot) {
			s.Peers[0].Kubernetes = access(KubernetesGrant{"view", now}, KubernetesGrant{"view", now})
		},
		"65 grants": func(s *Snapshot) {
			grants := make([]KubernetesGrant, 65)
			for index := range grants {
				grants[index] = KubernetesGrant{fmt.Sprintf("g%03d", index), now}
			}
			s.Peers[0].Kubernetes = access(grants...)
		},
		"owner text": func(s *Snapshot) {
			s.Peers[0].Kubernetes = &KubernetesAccess{Grants: []KubernetesGrant{{"view", now}}, OwnerRef: "alice"}
		},
		"unsorted tags": func(s *Snapshot) {
			s.Peers[0].Kubernetes = &KubernetesAccess{
				Grants:   []KubernetesGrant{{"view", now}},
				OwnerRef: "tags:" + tagID(2) + "," + tagID(1),
			}
		},
		"257 tags": func(s *Snapshot) {
			s.Peers[0].Kubernetes = &KubernetesAccess{
				Grants:   []KubernetesGrant{{"view", now}},
				OwnerRef: tagsOwner(257),
			}
		},
	} {
		broken := validSnapshot()
		mutate(&broken)
		if _, err := ValidateAndClone(broken, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
