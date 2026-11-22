package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// A cluster's trust as the Console shows it (V1-12 step 1g, schema 311).

const readKubernetesClusterTrustSQL = `SELECT mesh_ops.read_kubernetes_cluster_trust_v1(` + sessionArguments +
	`,$10::UUID,$11::UUID,$12::UUID)::TEXT`

// maximumInstallTokensRead is how many install tokens the read lists.
const maximumInstallTokensRead = 32

var _ kubecluster.ClusterTrustReader = (*KubernetesClusterStore)(nil)

type kubernetesTrustSideDocument struct {
	Digest         string   `json:"digest"`
	Issuer         string   `json:"issuer"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	StatefulSet    string   `json:"statefulset"`
	KeyThumbprints []string `json:"key_thumbprints"`
}

type kubernetesContestedDocument struct {
	kubernetesTrustSideDocument
	ContestedAt time.Time `json:"contested_at"`
}

type kubernetesTrustReadDocument struct {
	kubernetesTrustSideDocument
	TrustID     string                       `json:"trust_id"`
	Version     int64                        `json:"version"`
	Source      string                       `json:"source"`
	State       string                       `json:"state"`
	SetAt       time.Time                    `json:"set_at"`
	ConfirmedAt *time.Time                   `json:"confirmed_at"`
	ConfirmedBy *string                      `json:"confirmed_by"`
	Contested   *kubernetesContestedDocument `json:"contested"`
}

type kubernetesInstallTokenDocument struct {
	KeyID        string    `json:"key_id"`
	State        string    `json:"state"`
	Replicas     int       `json:"replicas"`
	UsedOrdinals []int     `json:"used_ordinals"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ReadClusterTrust authorizes network.read and reads the cluster's trust
// mode and trust; install tokens only for those with kubernetes_cluster.manage.
func (store *KubernetesClusterStore) ReadClusterTrust(ctx context.Context, session accountsession.Session,
	scope network.Scope, id kubecluster.ID) (kubecluster.ClusterTrustView, error) {
	var view kubecluster.ClusterTrustView
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesClusterTrustSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), id.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var read struct {
			NetworkID      string                           `json:"network_id"`
			ClusterID      string                           `json:"cluster_id"`
			ClusterVersion int64                            `json:"cluster_version"`
			TrustMode      string                           `json:"trust_mode"`
			Trust          *kubernetesTrustReadDocument     `json:"trust"`
			CanManage      bool                             `json:"can_manage"`
			Tokens         []kubernetesInstallTokenDocument `json:"install_tokens"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil ||
			read.NetworkID != scope.NetworkID().String() || read.ClusterID != id.String() ||
			read.ClusterVersion <= 0 || (read.Tokens != nil) != read.CanManage ||
			len(read.Tokens) > maximumInstallTokensRead {
			return false, kubecluster.ErrInvalid
		}
		mode := kubecluster.TrustMode(read.TrustMode)
		if !mode.IsKnown() && mode != "issuer" {
			return false, kubecluster.ErrInvalid
		}
		view = kubecluster.ClusterTrustView{ClusterVersion: read.ClusterVersion, Mode: mode, CanManage: read.CanManage}
		if read.Trust != nil {
			trust, err := read.Trust.read()
			if err != nil {
				return false, err
			}
			view.Trust = &trust
		}
		for _, document := range read.Tokens {
			token, err := document.state()
			if err != nil {
				return false, err
			}
			view.Tokens = append(view.Tokens, token)
		}
		return false, nil
	})
	return view, err
}

func (document kubernetesTrustSideDocument) side() (kubecluster.TrustSide, error) {
	digest, ok := decodeThumbprint(document.Digest)
	if !ok || !kubejoin.ValidIssuer(document.Issuer) || !kubejoin.ValidNamespace(document.Namespace) ||
		!kubejoin.ValidName(document.ServiceAccount) || !kubejoin.ValidName(document.StatefulSet) ||
		len(document.KeyThumbprints) == 0 || len(document.KeyThumbprints) > maximumTrustKeys {
		return kubecluster.TrustSide{}, kubecluster.ErrInvalid
	}
	side := kubecluster.TrustSide{Digest: digest, Issuer: document.Issuer, Namespace: document.Namespace,
		ServiceAccount: document.ServiceAccount, StatefulSet: document.StatefulSet}
	for _, encoded := range document.KeyThumbprints {
		thumbprint, ok := decodeThumbprint(encoded)
		if !ok {
			return kubecluster.TrustSide{}, kubecluster.ErrInvalid
		}
		side.KeyThumbprints = append(side.KeyThumbprints, thumbprint)
	}
	return side, nil
}

func (document kubernetesTrustReadDocument) read() (kubecluster.ClusterTrustRead, error) {
	id, err := publicid.Parse(document.TrustID)
	source, state := kubecluster.TrustSource(document.Source), kubecluster.TrustState(document.State)
	if err != nil || document.Version <= 0 || !source.IsKnown() || document.SetAt.IsZero() ||
		(state != kubecluster.TrustConfirmed && state != kubecluster.TrustUnconfirmed &&
			state != kubecluster.TrustContested) || (state == kubecluster.TrustContested) != (document.Contested != nil) {
		return kubecluster.ClusterTrustRead{}, kubecluster.ErrInvalid
	}
	side, err := document.side()
	if err != nil {
		return kubecluster.ClusterTrustRead{}, err
	}
	trust := kubecluster.ClusterTrustRead{ID: id, Version: document.Version, Source: source, State: state,
		Side: side, SetAt: document.SetAt}
	// Who confirmed it is read only by those who manage the cluster.
	if document.ConfirmedAt == nil && document.ConfirmedBy != nil {
		return kubecluster.ClusterTrustRead{}, kubecluster.ErrInvalid
	}
	if document.ConfirmedAt != nil {
		trust.ConfirmedAt = *document.ConfirmedAt
	}
	if document.ConfirmedBy != nil {
		confirmer, err := publicid.Parse(*document.ConfirmedBy)
		if err != nil {
			return kubecluster.ClusterTrustRead{}, kubecluster.ErrInvalid
		}
		trust.ConfirmedBy = confirmer
	}
	if document.Contested != nil {
		other, err := document.Contested.side()
		if err != nil || document.Contested.ContestedAt.IsZero() {
			return kubecluster.ClusterTrustRead{}, kubecluster.ErrInvalid
		}
		trust.Contested, trust.ContestedAt = &other, document.Contested.ContestedAt
	}
	return trust, nil
}

func (document kubernetesInstallTokenDocument) state() (kubecluster.InstallTokenState, error) {
	keyID, err := enrollment.ParseCredentialID(document.KeyID)
	creator, creatorErr := publicid.Parse(document.CreatedBy)
	if err != nil || creatorErr != nil || document.Replicas < 1 ||
		document.Replicas > kubecluster.MaxInstallTokenReplicas || len(document.UsedOrdinals) > document.Replicas ||
		document.CreatedAt.IsZero() || document.ExpiresAt.IsZero() {
		return kubecluster.InstallTokenState{}, kubecluster.ErrInvalid
	}
	switch document.State {
	case "active", "expired", "revoked":
	default:
		return kubecluster.InstallTokenState{}, kubecluster.ErrInvalid
	}
	for _, ordinal := range document.UsedOrdinals {
		if ordinal < 0 || ordinal >= document.Replicas {
			return kubecluster.InstallTokenState{}, kubecluster.ErrInvalid
		}
	}
	return kubecluster.InstallTokenState{KeyID: keyID, State: document.State, Replicas: document.Replicas,
		UsedOrdinals: document.UsedOrdinals, CreatedBy: creator, CreatedAt: document.CreatedAt,
		ExpiresAt: document.ExpiresAt}, nil
}
