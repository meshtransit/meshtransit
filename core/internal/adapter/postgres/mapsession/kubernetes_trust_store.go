package mapsession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
)

// Schema 244 (K1a4d design §3.1): v2 of the map CA reader names what a
// client trusts its clusters' gateways by, besides what a gateway's map
// names; the roots' DER is read apart, by fingerprint.
const (
	kubernetesTrustGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_cas_v2(integer)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_kubernetes_ca_roots_v1(bytea[])'), 'EXECUTE'), FALSE)`
	loadKubernetesCAsV2SQL   = `SELECT mesh_ops.load_map_network_kubernetes_cas_v2($1::INTEGER)::TEXT`
	loadKubernetesRootsSQL   = `SELECT mesh_ops.load_map_kubernetes_ca_roots_v1($1::BYTEA[])::TEXT`
	kubernetesCAsSavepoint   = `SAVEPOINT kubernetes_cas`
	kubernetesCAsRollback    = `ROLLBACK TO SAVEPOINT kubernetes_cas`
	kubernetesCAsRelease     = `RELEASE SAVEPOINT kubernetes_cas`
	kubernetesRootsSavepoint = `SAVEPOINT kubernetes_roots`
	kubernetesRootsRollback  = `ROLLBACK TO SAVEPOINT kubernetes_roots`
	kubernetesRootsRelease   = `RELEASE SAVEPOINT kubernetes_roots`
	// maximumKubernetesCAV2Payload fits maximumKubernetesCAClusters entries
	// of a UUID, a 63-byte name, a 253-byte TLS name and five hex
	// fingerprints: at most 772 bytes of jsonb text each, 7.7 MB for 10,001
	// (review d1 L10).
	maximumKubernetesCAV2Payload = 8 << 20
	// kubernetesRootsPerRead bounds the fingerprints of one DER read.
	kubernetesRootsPerRead = 1024
	// maximumKubernetesRootsPayload fits kubernetesRootsPerRead roots of
	// the 8 KiB the schema allows, in hex.
	maximumKubernetesRootsPayload = kubernetesRootsPerRead*8192*2 + 4096
)

// ErrKubernetesSavepoint reports a savepoint that could not be rolled back
// to: the inventory transaction is unusable.
var ErrKubernetesSavepoint = errors.New("mapsession: Kubernetes CA savepoint failed")

// kubernetesCARead is one inventory's read of its clusters' CAs: the
// gateways' (§7.10, when read) and the clients' trust.
type kubernetesCARead struct {
	gateway  map[kubecluster.Name]appmapsession.KubernetesCA
	read     bool
	withheld bool
	trust    appmapsession.KubernetesTrust
}

// readsKubernetesTrust reports whether this role may run both schema 244
// readers; once granted it is not probed again.
func (store *Store) readsKubernetesTrust(ctx context.Context, transaction databaseTransaction) (bool, error) {
	if store.kubernetesTrustGranted.Load() {
		return true, nil
	}
	granted, err := functionGranted(ctx, transaction, kubernetesTrustGrantedSQL)
	if err != nil {
		return false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check Kubernetes trust reader: %w", err))
	}
	if granted {
		store.kubernetesTrustGranted.Store(true)
	}
	return granted, nil
}

// readKubernetesCAsV2 reads the Network's clusters' CAs with schema 244,
// behind a savepoint: a failed read leaves the transaction usable and
// answers false, so the gateways' CAs fall back to v1 and the clients'
// trust is unread (design §3.2). The roots' DER comes from previous (the
// Network's last inventory), the shared cache, then the database.
func (store *Store) readKubernetesCAsV2(ctx context.Context, transaction databaseTransaction,
	previous appmapsession.KubernetesTrust,
) (kubernetesCARead, bool, error) {
	var encoded string
	rolledBack, err := store.withSavepoint(ctx, transaction, kubernetesCAsSavepoint, kubernetesCAsRollback,
		kubernetesCAsRelease, func() error {
			return scanOne(ctx, transaction, loadKubernetesCAsV2SQL, &encoded, maximumKubernetesCAClusters+1)
		})
	if err != nil || rolledBack {
		return kubernetesCARead{}, false, err
	}
	result, clusters, dropped, ok := decodeKubernetesCAsV2(encoded)
	if !ok {
		return kubernetesCARead{}, false, nil
	}
	if result.withheld {
		result.trust = appmapsession.UnavailableKubernetesTrust(appmapsession.KubernetesTrustRestore)
		return result, true, nil
	}
	roots, err := store.kubernetesRoots(ctx, transaction, clusters, previous)
	if err != nil {
		return kubernetesCARead{}, false, err
	}
	trust, ok := appmapsession.NewKubernetesTrust(clusters, roots)
	if !ok {
		return kubernetesCARead{}, false, nil
	}
	store.stats.kubernetesGatewayCAsOmitted.Add(uint64(dropped))
	result.trust = trust
	return result, true, nil
}

// kubernetesRoots gathers the DER of every root the clusters name: from the
// Network's previous inventory, the shared cache, then the database behind
// a savepoint, a batch at a time. A root it cannot get is left out (the
// cluster then shows incomplete) and counted; only a savepoint that cannot
// be rolled back to fails.
func (store *Store) kubernetesRoots(ctx context.Context, transaction databaseTransaction,
	clusters []appmapsession.KubernetesClusterTrust, previous appmapsession.KubernetesTrust,
) (map[[32]byte][]byte, error) {
	roots := map[[32]byte][]byte{}
	var missing [][32]byte
	asked := map[[32]byte]struct{}{}
	for _, cluster := range clusters {
		for _, fingerprint := range cluster.Roots {
			if _, seen := asked[fingerprint]; seen {
				continue
			}
			asked[fingerprint] = struct{}{}
			if der, ok := previous.Root(fingerprint); ok {
				// Verified when the previous inventory read it.
				roots[fingerprint] = der
				store.kubernetesRootCache.keep(fingerprint, der)
				continue
			}
			if der, ok := store.kubernetesRootCache.get(fingerprint); ok {
				roots[fingerprint] = der
				continue
			}
			missing = append(missing, fingerprint)
		}
	}
	for batch := range slices.Chunk(missing, kubernetesRootsPerRead) {
		read, err := store.readKubernetesRoots(ctx, transaction, batch)
		if err != nil {
			return nil, err
		}
		for fingerprint, der := range read {
			roots[fingerprint] = der
			store.kubernetesRootCache.put(fingerprint, der)
		}
	}
	for _, fingerprint := range missing {
		if _, held := roots[fingerprint]; !held {
			store.stats.kubernetesRootsMissing.Add(1)
		}
	}
	return roots, nil
}

// readKubernetesRoots reads one batch of roots' DER behind a savepoint: a
// failed or untrusted read returns none.
func (store *Store) readKubernetesRoots(ctx context.Context, transaction databaseTransaction,
	batch [][32]byte,
) (map[[32]byte][]byte, error) {
	fingerprints := make([][]byte, len(batch))
	for index := range batch {
		fingerprints[index] = batch[index][:]
	}
	var encoded string
	rolledBack, err := store.withSavepoint(ctx, transaction, kubernetesRootsSavepoint, kubernetesRootsRollback,
		kubernetesRootsRelease, func() error {
			return scanOne(ctx, transaction, loadKubernetesRootsSQL, &encoded, fingerprints)
		})
	if err != nil || rolledBack {
		return nil, err
	}
	return decodeKubernetesRoots(encoded, batch), nil
}

// decodeKubernetesRoots keeps each root whose DER is one of batch's
// fingerprints; none when the answer cannot be trusted or is withheld.
func decodeKubernetesRoots(encoded string, batch [][32]byte) map[[32]byte][]byte {
	if len(encoded) > maximumKubernetesRootsPayload {
		return nil
	}
	var record struct {
		Withheld *bool    `json:"withheld"`
		Roots    []string `json:"roots"`
	}
	if !decodeStrict(encoded, &record) || record.Withheld == nil || *record.Withheld || len(record.Roots) > len(batch) {
		return nil
	}
	roots := make(map[[32]byte][]byte, len(record.Roots))
	for _, entry := range record.Roots {
		der, err := hex.DecodeString(entry)
		fingerprint := sha256.Sum256(der)
		if err != nil || !slices.Contains(batch, fingerprint) {
			return nil
		}
		roots[fingerprint] = der
	}
	return roots
}

// decodeKubernetesCAsV2 reads v2's answer: the gateways' CAs (signing_root
// is v1's root) and the clusters a client trusts; false when it cannot be
// trusted. A cluster whose gateway root is not one it trusts, which schema
// 239 never allows but a hand repair could, keeps its clients' trust (the
// database's truth) and is left out of the gateways' CAs only (§7.10
// absent: its gateways keep their certificates), counted in omitted; the
// Network's other clusters are untouched (review d1 L8).
func decodeKubernetesCAsV2(encoded string) (
	result kubernetesCARead, clusters []appmapsession.KubernetesClusterTrust, omitted int, ok bool,
) {
	if len(encoded) > maximumKubernetesCAV2Payload {
		return kubernetesCARead{}, nil, 0, false
	}
	var record struct {
		Withheld *bool `json:"withheld"`
		Clusters []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Signing     *string  `json:"signing"`
			SigningRoot *string  `json:"signing_root"`
			TLSName     *string  `json:"tls_name"`
			Trusted     []string `json:"trusted"`
		} `json:"clusters"`
	}
	if !decodeStrict(encoded, &record) || record.Withheld == nil || len(record.Clusters) > maximumKubernetesCAClusters {
		return kubernetesCARead{}, nil, 0, false
	}
	if *record.Withheld {
		return kubernetesCARead{withheld: true}, nil, 0, len(record.Clusters) == 0
	}
	result = kubernetesCARead{
		gateway: make(map[kubecluster.Name]appmapsession.KubernetesCA, len(record.Clusters)), read: true,
	}
	clusters = make([]appmapsession.KubernetesClusterTrust, 0, len(record.Clusters))
	seen := make(map[kubecluster.Name]struct{}, len(record.Clusters))
	for _, entry := range record.Clusters {
		id, idErr := kubecluster.ParseID(entry.ID)
		name, nameErr := kubecluster.ParseName(entry.Name)
		if _, duplicate := seen[name]; idErr != nil || nameErr != nil || duplicate ||
			entry.Trusted == nil || len(entry.Trusted) > appmapsession.MaximumKubernetesTrustRoots {
			return kubernetesCARead{}, nil, 0, false
		}
		cluster := appmapsession.KubernetesClusterTrust{ID: id, Name: name, Roots: make([][32]byte, 0, len(entry.Trusted))}
		for _, trusted := range entry.Trusted {
			fingerprint, ok := decodeFingerprint(&trusted)
			if !ok {
				return kubernetesCARead{}, nil, 0, false
			}
			cluster.Roots = append(cluster.Roots, [32]byte(fingerprint))
		}
		if entry.TLSName != nil {
			if !validTLSName(*entry.TLSName) {
				return kubernetesCARead{}, nil, 0, false
			}
			cluster.TLSName = *entry.TLSName
		}
		ca := appmapsession.KubernetesCA{}
		var ok bool
		if ca.Root, ok = decodeOptionalFingerprint(entry.SigningRoot); !ok {
			return kubernetesCARead{}, nil, 0, false
		}
		if ca.Signing, ok = decodeOptionalFingerprint(entry.Signing); !ok {
			return kubernetesCARead{}, nil, 0, false
		}
		// The gateway's root is one a client trusts (schema 239 keeps a
		// root active while an intermediate it signed is).
		if !ca.Valid() {
			return kubernetesCARead{}, nil, 0, false
		}
		seen[name] = struct{}{}
		clusters = append(clusters, cluster)
		if len(ca.Root) == 32 && !slices.Contains(cluster.Roots, [32]byte(ca.Root)) {
			omitted++
			continue
		}
		result.gateway[name] = ca
	}
	return result, clusters, omitted, true
}

// decodeFingerprint decodes a hex SHA-256.
func decodeFingerprint(encoded *string) ([]byte, bool) {
	decoded, err := hex.DecodeString(*encoded)
	return decoded, err == nil && len(decoded) == sha256.Size
}

// decodeOptionalFingerprint decodes a hex SHA-256 or null (none).
func decodeOptionalFingerprint(encoded *string) ([]byte, bool) {
	if encoded == nil {
		return nil, true
	}
	return decodeFingerprint(encoded)
}

// validTLSName accepts the cluster DNS names schema 239 stores.
func validTLSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || name[0] == '.' || name[0] == '-' ||
		name[len(name)-1] == '.' || name[len(name)-1] == '-' {
		return false
	}
	for _, character := range []byte(name) {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '-') {
			return false
		}
	}
	return true
}

// decodeStrict decodes exactly one JSON value without unknown fields.
func decodeStrict(encoded string, into any) bool {
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

// scanOne runs a query answering one text value.
func scanOne(ctx context.Context, transaction databaseTransaction, query string, into *string, arguments ...any) error {
	rows, err := transaction.Query(ctx, query, arguments...)
	if err != nil || rows == nil {
		return nonNil(err)
	}
	defer rows.Close()
	if !rows.Next() {
		return errors.Join(errors.New("no answer"), rows.Err())
	}
	if err := rows.Scan(into); err != nil {
		return err
	}
	return rows.Err()
}

// withSavepoint runs read behind a savepoint and reports it to the observer
// (OperationReadKubernetesTrust, so a fallback's cause shows by class). A
// failed read is rolled back to it (its rows closed first) and reported as
// rolledBack; err is set only when the savepoint itself fails, leaving the
// transaction unusable.
func (store *Store) withSavepoint(ctx context.Context, transaction databaseTransaction,
	savepoint, rollback, release string, read func() error,
) (rolledBack bool, err error) {
	if err := transaction.Exec(ctx, savepoint); err != nil {
		return false, errors.Join(ErrLoadSnapshot, ErrKubernetesSavepoint, err)
	}
	startedAt := time.Now()
	readErr := read()
	store.observer.ObserveMapSession(OperationReadKubernetesTrust, time.Since(startedAt), readErr)
	if readErr != nil {
		if err := transaction.Exec(ctx, rollback); err != nil {
			return false, errors.Join(ErrLoadSnapshot, ErrKubernetesSavepoint, readErr, err)
		}
		return true, nil
	}
	if err := transaction.Exec(ctx, release); err != nil {
		return false, errors.Join(ErrLoadSnapshot, ErrKubernetesSavepoint, err)
	}
	return false, nil
}

// readInventoryKubernetesCAs reads, with the inventory and of its revision,
// the Network's clusters' CAs: the gateways' (§7.10) and the clients'
// trust (K1a4d). Schema 244 first, behind a savepoint; when it is not
// granted, fails or cannot be trusted, the gateways' come from schema 242
// and the clients' trust stays unread.
func (store *Store) readInventoryKubernetesCAs(ctx context.Context, transaction databaseTransaction,
	previous cachedInventory, cached *cachedInventory,
) error {
	cached.kubernetesTrust = appmapsession.UnavailableKubernetesTrust(appmapsession.KubernetesTrustUnread)
	trusted, err := store.readsKubernetesTrust(ctx, transaction)
	if err != nil {
		return err
	}
	if trusted {
		result, ok, err := store.readKubernetesCAsV2(ctx, transaction, previous.kubernetesTrust)
		if err != nil {
			return err
		}
		if ok {
			cached.kubernetesCAs, cached.kubernetesCAsRead = result.gateway, result.read
			cached.kubernetesTrust = result.trust
			if result.withheld {
				store.stats.kubernetesCAsWithheld.Add(1)
			}
			return nil
		}
		store.stats.kubernetesTrustUnread.Add(1)
	}
	granted, err := store.readsKubernetesCAs(ctx, transaction)
	if err != nil || !granted {
		return err
	}
	var withheld bool
	if cached.kubernetesCAs, cached.kubernetesCAsRead, withheld, err = readKubernetesCAs(ctx,
		transaction); err != nil {
		return err
	}
	// Gateways keep their certificates meanwhile; counted so operators see
	// that renewing on a CA change is off.
	switch {
	case withheld:
		store.stats.kubernetesCAsWithheld.Add(1)
	case !cached.kubernetesCAsRead:
		store.stats.kubernetesCAsRejected.Add(1)
	}
	return nil
}

// KubernetesTrustGranted reports, in a read of its own, whether this role
// may run schema 244's readers. Core offers kube.ca1 only then: a session
// it is offered to must find its clusters' trust read (K1a4d design §2.1).
func (store *Store) KubernetesTrustGranted(ctx context.Context) (granted bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil {
		return false, ErrInvalidStore
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return false, errors.Join(ErrLoadSnapshot, nonNil(err))
	}
	defer func() { resultErr = errors.Join(resultErr, rollback(transaction)) }()
	return functionGranted(ctx, transaction, kubernetesTrustGrantedSQL)
}
