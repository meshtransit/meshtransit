package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

func caProofJSON(aggregate, action, permission string, row publicid.ID, payload string) string {
	hash := sha256.Sum256([]byte(payload))
	return `{"outcome":"changed","aggregate":"` + aggregate + `","action":"` + action + `","permission":"` +
		permission + `","row_id":"` + row.String() + `","version":1,"network_revision":4,"semantic_hash":"` +
		hex.EncodeToString(hash[:]) + `","stream_id":2,"sequence":9,"previous_hash":"` + strings.Repeat("ab", 32) +
		`","payload":"` + strings.ReplaceAll(payload, `"`, `\"`) + `"}`
}

func TestDecodeCAProof(t *testing.T) {
	t.Parallel()
	row, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	other, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	operator := kubeca.Operator{Name: "alice", ChangeRef: "CHG-1"}
	created := caProofJSON(clusterCAAggregateKind, "kubernetes_cluster.ca_created", "system.reconcile", row,
		`{"format": "kubernetes-cluster-ca/v2"}`)
	proof, err := decodeCAProof(created, clusterCAAggregateKind, row, kubeca.Operator{})
	if err != nil || proof.Sequence != 9 || proof.Version != 1 {
		t.Fatalf("decodeCAProof() = %+v, %v", proof, err)
	}
	if _, _, err := hashCAEvent(proof, row, row); err != nil {
		t.Fatalf("hashCAEvent() = %v", err)
	}
	rewrapped := caProofJSON(caDataKeyAggregateKind, "kubernetes_ca_data_key.rewrapped", "system.operator", row, `{}`)
	if _, err := decodeCAProof(rewrapped, caDataKeyAggregateKind, row, operator); err != nil {
		t.Fatalf("an operator's rewrap: %v", err)
	}
	for name, test := range map[string]struct {
		encoded   string
		aggregate string
		operator  kubeca.Operator
		want      error
	}{
		"busy":                 {`{"outcome":"busy"}`, clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCABusy},
		"stale":                {`{"outcome":"stale"}`, clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStale},
		"busy with ids":        {`{"outcome":"busy","version":1}`, clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
		"another row":          {strings.Replace(created, row.String(), other.String(), 1), clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
		"another kind":         {created, caDataKeyAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
		"unknown action":       {strings.Replace(created, "ca_created", "ca_moved", 1), clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
		"operator said worker": {created, clusterCAAggregateKind, operator, ErrKubernetesClusterCAStore},
		"worker said operator": {rewrapped, caDataKeyAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
		"another payload": {
			strings.Replace(created, `"payload":"{`, `"payload":"[{`, 1), clusterCAAggregateKind,
			kubeca.Operator{},
			ErrKubernetesClusterCAStore,
		},
		"unknown field": {`{"outcome":"stale","extra":1}`, clusterCAAggregateKind, kubeca.Operator{}, ErrKubernetesClusterCAStore},
	} {
		if _, err := decodeCAProof(test.encoded, test.aggregate, row, test.operator); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
}

func TestDecodeClusterCANetwork(t *testing.T) {
	t.Parallel()
	if _, outcome, err := decodeClusterCANetwork(`{"outcome":"busy"}`); outcome != "busy" || err != nil {
		t.Fatalf("busy = %q, %v", outcome, err)
	}
	const ids = `"id":"0190f000-0000-7000-8000-000000000001"`
	key := `{` + ids + `,"version":1,"active":true,"custody":"file","key_id":"k1","ciphertext":"00ff"}`
	stamps := func(state string) string {
		const at = `"2026-10-28T00:00:00+00:00"`
		switch state {
		case "active":
			return `"activated_at":` + at + `,"retiring_at":null`
		case "retiring":
			return `"activated_at":` + at + `,"retiring_at":` + at
		}
		return `"activated_at":null,"retiring_at":null`
	}
	ca := func(kind, issuer, state, sealed string) string {
		return `{` + ids + `,"version":1,"kind":"` + kind + `","issuer_id":` + issuer + `,"state":"` + state +
			`","reason":"initial","data_key_id":"0190f000-0000-7000-8000-000000000002","certificate":"3082",` +
			`"cluster_dns_name":"prod.kube.example","not_before":"2026-10-28T00:00:00+00:00",` +
			`"not_after":"2036-10-28T00:00:00+00:00","sealed_key":` + sealed + `,` +
			`"created_at":"2026-10-28T00:00:00+00:00",` + stamps(state) + `}`
	}
	const issuer = `"0190f000-0000-7000-8000-000000000003"`
	network := func(outcome, cas string) string {
		return `{"outcome":"` + outcome + `","now":"2026-10-28T01:00:00.5+00:00","workspace_code":"123456789012",` +
			`"network_code":"210987654321","data_keys":[` + key + `],"clusters":[{` + ids +
			`,"name":"prod","state":"active","next_action_at":"2026-10-28T01:00:00+00:00","failures":0,"cas":[` +
			cas + `]}]}`
	}
	read, outcome, err := decodeClusterCANetwork(network("locked",
		ca("root", "null", "active", `"abcd"`)+","+ca("intermediate", issuer, "active", `"abcd"`)))
	if err != nil || outcome != "locked" || len(read.Clusters) != 1 || len(read.Clusters[0].CAs) != 2 ||
		read.Clusters[0].CAs[0].Kind != kubeca.KindRoot || read.Clusters[0].CAs[1].Kind != kubeca.KindIntermediate ||
		read.Clusters[0].CAs[1].IssuerID.String() != strings.Trim(issuer, `"`) || read.DataKeys[0].Version != 1 ||
		!read.DataKeys[0].Active || read.WorkspaceCode != "123456789012" {
		t.Fatalf("decodeClusterCANetwork() = %+v, %q, %v", read, outcome, err)
	}
	if _, outcome, err := decodeClusterCANetwork(network("read", ca("root", "null", "retiring", "null"))); err != nil ||
		outcome != "read" {
		t.Fatalf("a retiring root: %q, %v", outcome, err)
	}
	for name, encoded := range map[string]string{
		"a signing CA without its key": network("locked", ca("root", "null", "active", "null")),
		"a retiring CA with its key":   network("locked", ca("root", "null", "retiring", `"abcd"`)),
		"a retired CA":                 network("locked", ca("root", "null", "retired", "null")),
		"a root with an issuer":        network("locked", ca("root", issuer, "active", `"abcd"`)),
		"an intermediate without one":  network("locked", ca("intermediate", "null", "active", `"abcd"`)),
		"a next intermediate":          network("locked", ca("intermediate", issuer, "next", `"abcd"`)),
		"an unknown kind":              network("locked", ca("leaf", "null", "active", `"abcd"`)),
		"an unknown outcome":           network("stale", ""),
		"an active CA never activated": strings.Replace(network("locked", ca("root", "null", "active", `"abcd"`)),
			`"activated_at":"2026-10-28T00:00:00+00:00"`, `"activated_at":null`, 1),
		"no codes": strings.Replace(network("locked", ""), `"123456789012"`, "null", 1),
	} {
		if _, _, err := decodeClusterCANetwork(encoded); !errors.Is(err, ErrKubernetesClusterCAStore) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
