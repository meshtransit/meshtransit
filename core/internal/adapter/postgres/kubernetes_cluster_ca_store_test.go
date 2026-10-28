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

func clusterCAProofJSON(ca publicid.ID, payload string) string {
	hash := sha256.Sum256([]byte(payload))
	return `{"outcome":"changed","action":"kubernetes_cluster.ca_created","ca_id":"` + ca.String() +
		`","version":1,"network_revision":4,"semantic_hash":"` + hex.EncodeToString(hash[:]) +
		`","stream_id":2,"sequence":9,"previous_hash":"` + strings.Repeat("ab", 32) + `","payload":"` +
		strings.ReplaceAll(payload, `"`, `\"`) + `"}`
}

func TestDecodeClusterCAProof(t *testing.T) {
	t.Parallel()
	ca, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := decodeClusterCAProof(clusterCAProofJSON(ca, `{"format": "kubernetes-cluster-ca/v1"}`), ca)
	if err != nil || proof.Sequence != 9 || proof.Version != 1 {
		t.Fatalf("decodeClusterCAProof() = %+v, %v", proof, err)
	}
	if _, _, err := hashClusterCAEvent(proof, ca, ca); err != nil {
		t.Fatalf("hashClusterCAEvent() = %v", err)
	}
	other, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		encoded string
		want    error
	}{
		"busy":          {`{"outcome":"busy"}`, ErrKubernetesClusterCABusy},
		"stale":         {`{"outcome":"stale"}`, ErrKubernetesClusterCAStale},
		"busy with ids": {`{"outcome":"busy","version":1}`, ErrKubernetesClusterCAStore},
		"another CA":    {clusterCAProofJSON(other, `{}`), ErrKubernetesClusterCAStore},
		"unknown action": {
			strings.Replace(clusterCAProofJSON(ca, `{}`), "ca_created", "ca_moved", 1),
			ErrKubernetesClusterCAStore,
		},
		"another payload": {
			strings.Replace(clusterCAProofJSON(ca, `{}`), `"payload":"{}"`, `"payload":"[]"`, 1),
			ErrKubernetesClusterCAStore,
		},
		"unknown field": {`{"outcome":"stale","extra":1}`, ErrKubernetesClusterCAStore},
	} {
		if _, err := decodeClusterCAProof(test.encoded, ca); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
}

func TestDecodeClusterCANetwork(t *testing.T) {
	t.Parallel()
	if _, locked, err := decodeClusterCANetwork(`{"outcome":"busy"}`); locked || err != nil {
		t.Fatalf("busy = %v, %v", locked, err)
	}
	const ids = `"id":"0190f000-0000-7000-8000-000000000001"`
	key := `{` + ids + `,"custody":"file","key_id":"k1","ciphertext":"00ff","active":true}`
	ca := func(state, sealed string) string {
		return `{` + ids + `,"version":1,"state":"` + state + `","reason":"initial",` +
			`"data_key_id":"0190f000-0000-7000-8000-000000000002","certificate":"3082",` +
			`"cluster_dns_name":"prod.kube.example","not_before":"2026-10-28T00:00:00+00:00",` +
			`"not_after":"2028-10-28T00:00:00+00:00","sealed_key":` + sealed + `,` +
			`"created_at":"2026-10-28T00:00:00+00:00","activated_at":null,"retiring_at":null}`
	}
	network := func(cas string) string {
		return `{"outcome":"locked","now":"2026-10-28T01:00:00.5+00:00","workspace_code":"123456789012",` +
			`"network_code":"210987654321","data_keys":[` + key + `],"clusters":[{` + ids +
			`,"name":"prod","state":"active","next_action_at":"2026-10-28T01:00:00+00:00","failures":0,"cas":[` +
			cas + `]}]}`
	}
	read, locked, err := decodeClusterCANetwork(network(ca("next", `"abcd"`)))
	if err != nil || !locked || len(read.Clusters) != 1 || len(read.Clusters[0].CAs) != 1 ||
		read.Clusters[0].CAs[0].State != kubeca.StateNext || len(read.Clusters[0].CAs[0].SealedKey) != 2 ||
		!read.DataKeys[0].Active || read.WorkspaceCode != "123456789012" {
		t.Fatalf("decodeClusterCANetwork() = %+v, %v, %v", read, locked, err)
	}
	if _, _, err := decodeClusterCANetwork(network(ca("retiring", "null"))); err != nil {
		t.Fatalf("a retiring CA: %v", err)
	}
	for name, encoded := range map[string]string{
		"a signing CA without its key": network(ca("active", "null")),
		"a retiring CA with its key":   network(ca("retiring", `"abcd"`)),
		"a retired CA":                 network(ca("retired", "null")),
		"no codes":                     strings.Replace(network(""), `"123456789012"`, "null", 1),
	} {
		if _, _, err := decodeClusterCANetwork(encoded); !errors.Is(err, ErrKubernetesClusterCAStore) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
