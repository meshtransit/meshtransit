package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// kubernetesDefaultPageSize is the page of keys or requests without
// page_size: what the Console shows (K1d Q130).
const kubernetesDefaultPageSize = 10

type kubernetesPage struct {
	limit int
	after kubecluster.PageCursor
}

// kubernetesPageToken binds a cursor to its Network, cluster and list, so
// a token from one list never pages another.
type kubernetesPageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"w"`
	NetworkID   string `json:"n"`
	ClusterID   string `json:"c"`
	List        string `json:"l"`
	At          string `json:"t"`
	After       string `json:"a"`
}

func encodeKubernetesPageToken(scope network.Scope, clusterID kubecluster.ID, list string,
	cursor kubecluster.PageCursor) string {
	if cursor.IsZero() {
		return ""
	}
	payload, err := json.Marshal(kubernetesPageToken{Version: 1, WorkspaceID: scope.WorkspaceID().String(),
		NetworkID: scope.NetworkID().String(), ClusterID: clusterID.String(), List: list,
		At: cursor.At.UTC().Format(time.RFC3339Nano), After: cursor.ID.String()})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// parseKubernetesPage reads page_size and page_token, nothing else.
func parseKubernetesPage(raw string, scope network.Scope, clusterID kubecluster.ID,
	list string) (kubernetesPage, bool) {
	page := kubernetesPage{limit: kubernetesDefaultPageSize}
	if raw == "" {
		return page, true
	}
	if len(raw) > 1024 {
		return kubernetesPage{}, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return kubernetesPage{}, false
	}
	for key, entries := range values {
		if (key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return kubernetesPage{}, false
		}
	}
	if value := values.Get("page_size"); value != "" {
		page.limit, err = strconv.Atoi(value)
		if err != nil || page.limit < 1 || page.limit > kubecluster.MaximumPageSize ||
			strconv.Itoa(page.limit) != value {
			return kubernetesPage{}, false
		}
	}
	encoded := values.Get("page_token")
	if encoded == "" {
		return page, true
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(encoded) > 512 || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return kubernetesPage{}, false
	}
	var wire kubernetesPageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() ||
		wire.ClusterID != clusterID.String() || wire.List != list {
		return kubernetesPage{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, wire.At)
	if err != nil {
		return kubernetesPage{}, false
	}
	after, err := publicid.Parse(wire.After)
	if err != nil || !after.IsValid() {
		return kubernetesPage{}, false
	}
	page.after = kubecluster.PageCursor{At: at.UTC(), ID: after}
	return page, true
}
