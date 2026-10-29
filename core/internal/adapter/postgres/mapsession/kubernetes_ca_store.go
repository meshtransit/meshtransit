package mapsession

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
)

const (
	kubernetesCAsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_cas_v1(integer)'), 'EXECUTE'), FALSE)`
	loadKubernetesCAsSQL = `SELECT mesh_ops.load_map_network_kubernetes_cas_v1($1::INTEGER)::TEXT`
	// maximumKubernetesCAClusters bounds the clusters of a Network read;
	// more withholds every cluster's CAs.
	maximumKubernetesCAClusters = 10000
	// maximumKubernetesCAPayload fits maximumKubernetesCAClusters entries of
	// a 63-byte name and two hex fingerprints (about 230 bytes each).
	maximumKubernetesCAPayload = 4 << 20
)

// readsKubernetesCAs reports whether this role may run the schema 242
// reader; once granted it is not probed again. Without it no gateway's map
// names its cluster's CAs.
func (store *Store) readsKubernetesCAs(ctx context.Context, transaction databaseTransaction) (bool, error) {
	if store.kubernetesCAsGranted.Load() {
		return true, nil
	}
	granted, err := functionGranted(ctx, transaction, kubernetesCAsGrantedSQL)
	if err != nil {
		return false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check Kubernetes CA reader: %w", err))
	}
	if granted {
		store.kubernetesCAsGranted.Store(true)
	}
	return granted, nil
}

// readKubernetesCAs reads the Network's clusters' root and signing CAs
// (mtcp-v1 §7.10), in the inventory's transaction. read is false when they
// are withheld (a restore suspected) or unreadable: the maps then carry
// none, and gateways keep their certificates.
func readKubernetesCAs(ctx context.Context, transaction databaseTransaction) (
	cas map[kubecluster.Name]appmapsession.KubernetesCA, read, withheld bool, err error,
) {
	rows, err := transaction.Query(ctx, loadKubernetesCAsSQL, maximumKubernetesCAClusters+1)
	if err != nil || rows == nil {
		return nil, false, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes CAs: %w", nonNil(err)))
	}
	defer rows.Close()
	var encoded string
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, false, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes CAs: %w", err))
		}
		return nil, false, false, nil
	}
	if err := rows.Scan(&encoded); err != nil {
		return nil, false, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes CAs: %w", err))
	}
	if err := rows.Err(); err != nil {
		return nil, false, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes CAs: %w", err))
	}
	cas, read, withheld = decodeKubernetesCAs(encoded)
	return cas, read, withheld, nil
}

// decodeKubernetesCAs reads the reader's answer; withheld when a restore is
// suspected, neither read nor withheld when it cannot be trusted.
func decodeKubernetesCAs(encoded string) (cas map[kubecluster.Name]appmapsession.KubernetesCA, read, withheld bool) {
	if len(encoded) > maximumKubernetesCAPayload {
		return nil, false, false
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	var record struct {
		Withheld *bool `json:"withheld"`
		Clusters []struct {
			Name    string  `json:"name"`
			Root    *string `json:"root"`
			Signing *string `json:"signing"`
		} `json:"clusters"`
	}
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		record.Withheld == nil || len(record.Clusters) > maximumKubernetesCAClusters {
		return nil, false, false
	}
	if *record.Withheld {
		return nil, false, true
	}
	cas = make(map[kubecluster.Name]appmapsession.KubernetesCA, len(record.Clusters))
	for _, cluster := range record.Clusters {
		name, err := kubecluster.ParseName(cluster.Name)
		if _, duplicate := cas[name]; err != nil || duplicate {
			return nil, false, false
		}
		ca := appmapsession.KubernetesCA{}
		for _, field := range []struct {
			encoded *string
			into    *[]byte
		}{{cluster.Root, &ca.Root}, {cluster.Signing, &ca.Signing}} {
			if field.encoded == nil {
				continue
			}
			decoded, err := hex.DecodeString(*field.encoded)
			if err != nil {
				return nil, false, false
			}
			*field.into = decoded
		}
		if !ca.Valid() {
			return nil, false, false
		}
		cas[name] = ca
	}
	return cas, true, false
}

// withKubernetesCA adds to a gateway replica's view its cluster's CAs, when
// the inventory read them: a cluster without CAs names none (both empty).
// Every active cluster is read, so one missing (left out, review d1 L8)
// leaves them absent (§7.10): its gateways keep their certificates.
func (cached cachedInventory) withKubernetesCA(view appmapsession.KubernetesView,
	cluster kubecluster.Name,
) appmapsession.KubernetesView {
	ca, read := cached.kubernetesCAs[cluster]
	if !cached.kubernetesCAsRead || !read {
		return view
	}
	return view.WithCA(ca)
}
