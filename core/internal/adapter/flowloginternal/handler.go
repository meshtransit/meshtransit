package flowloginternal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/flowlog"
)

const (
	keysPath        = "/internal/v1/flowlog/keys"
	revocationsPath = "/internal/v1/flowlog/revocations"
	networksPath    = "/internal/v1/flowlog/networks"
	scopedPrefix    = "/internal/v1/flowlog/workspaces/"
	// contentType is protobuf; the receiver refuses unknown fields.
	contentType = "application/x-protobuf"
	// The receiver polls a handful of paths every few seconds per replica.
	requestRate  = 50
	requestBurst = 200
	// revocationAge is how long one read of the revocations answers every
	// request of this replica (C46).
	revocationAge = time.Second
	// defaultNetworkPage is a networks page without limit=.
	defaultNetworkPage = 1000
	// gzipAbove compresses answers larger than this for a client that
	// accepts gzip.
	gzipAbove = 64 << 10
	// readTimeout bounds one database read of a request.
	readTimeout = 5 * time.Second
)

// Reader is what the internal API reads from Core's database.
type Reader interface {
	Networks(ctx context.Context, after network.ID, limit int) (connectionlog.ReceiverNetworks, error)
	Destination(ctx context.Context, scope network.Scope) (connectionlog.ReceiverDestination, error)
	Revocations(ctx context.Context) (connectionlog.ReceiverRevocations, error)
	Directory(ctx context.Context, scope network.Scope) (connectionlog.ReceiverDirectory, error)
}

var (
	// ErrNotFound is what a Reader answers for no such Network or no
	// destination.
	ErrNotFound = errors.New("flowloginternal: not found")
	// ErrRevocationsCut is what a Reader answers when more keys were
	// revoked than one answer lists: the API answers 503, never a cut list.
	ErrRevocationsCut = errors.New("flowloginternal: revocations cut")
)

// handler routes the internal API. It answers only GET, and every answer
// carries an ETag of its content so a poll that finds nothing new is 304.
type handler struct {
	keys         *flowlogv1.FlowSigningKeys
	keysTag      string
	reader       Reader
	status       StatusWriter
	limiter      *rate.Limiter
	statusLimits statusLimits
	metrics      *Metrics
	logger       *slog.Logger
	now          func() time.Time

	revocationMu sync.Mutex
	revocations  *cachedRevocations

	directories *directoryCache
}

// cachedRevocations is one read shared by the requests of revocationAge;
// done closes when it ends.
type cachedRevocations struct {
	done    chan struct{}
	readAt  time.Time
	message *flowlogv1.FlowRevocations
	tag     string
	err     error
}

func newHandler(options Options) (*handler, error) {
	if options.Reader == nil || options.Status == nil {
		return nil, ErrInvalidServer
	}
	keys := &flowlogv1.FlowSigningKeys{}
	current := 0
	for _, key := range options.TokenKeys {
		state, ok := keyStates[key.State]
		if !ok || len(key.Key) != ed25519.PublicKeySize {
			return nil, ErrInvalidServer
		}
		if state == flowlogv1.FlowSigningKeys_CURRENT {
			current++
		}
		keys.Keys = append(keys.Keys, &flowlogv1.FlowSigningKeys_Key{
			Kid: flowlog.SigningKeyID(key.Key), PublicKey: []byte(key.Key), State: state,
		})
	}
	if current != 1 {
		return nil, ErrInvalidServer
	}
	tag, err := contentTag(keys)
	if err != nil {
		return nil, ErrInvalidServer
	}
	return &handler{
		keys: keys, keysTag: tag, reader: options.Reader, status: options.Status,
		limiter: rate.NewLimiter(requestRate, requestBurst), statusLimits: newStatusLimits(),
		metrics: options.Metrics, logger: options.Logger, now: options.Now, directories: newDirectoryCache(),
	}, nil
}

var keyStates = map[string]flowlogv1.FlowSigningKeys_State{
	"current": flowlogv1.FlowSigningKeys_CURRENT, "next": flowlogv1.FlowSigningKeys_NEXT,
	"retiring": flowlogv1.FlowSigningKeys_RETIRING, "revoked": flowlogv1.FlowSigningKeys_REVOKED,
}

// contentTag is a strong ETag of message, which holds no time.
func contentTag(message proto.Message) (string, error) {
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`, nil
}

func (handler *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	route := routeOf(request.URL.Path)
	if route == "status" {
		handler.serveStatus(response, request)
		return
	}
	if !handler.limiter.Allow() {
		handler.metrics.request(route, "throttled")
		response.Header().Set("Retry-After", "1")
		http.Error(response, "too many requests", http.StatusTooManyRequests)
		return
	}
	if request.Method != http.MethodGet {
		handler.metrics.request(route, "method")
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch route {
	case "keys":
		keys := proto.CloneOf(handler.keys)
		keys.GeneratedAtMs = handler.now().UnixMilli()
		handler.answer(response, request, route, handler.keysTag, keys)
	case "revocations":
		handler.serveRevocations(response, request)
	case "networks":
		handler.serveNetworks(response, request)
	case "destination":
		handler.serveDestination(response, request)
	case "directory":
		handler.serveDirectory(response, request)
	default:
		handler.metrics.request(route, "not_found")
		http.NotFound(response, request)
	}
}

func (handler *handler) unavailable(response http.ResponseWriter, route string) {
	handler.metrics.request(route, "unavailable")
	response.Header().Set("Retry-After", "5")
	http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
}

func (handler *handler) serveRevocations(response http.ResponseWriter, request *http.Request) {
	read := handler.sharedRevocations()
	select {
	case <-read.done:
	case <-request.Context().Done():
		return
	}
	if errors.Is(read.err, ErrRevocationsCut) {
		handler.metrics.request("revocations", "cut")
		response.Header().Set("Retry-After", "5")
		http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if read.err != nil {
		handler.unavailable(response, "revocations")
		return
	}
	handler.answer(response, request, "revocations", read.tag, read.message)
}

// sharedRevocations starts a read when the last is older than
// revocationAge, and lets every request wait on the one in flight: the
// receiver's replicas cost one read a second (C46).
func (handler *handler) sharedRevocations() *cachedRevocations {
	handler.revocationMu.Lock()
	defer handler.revocationMu.Unlock()
	if current := handler.revocations; current != nil {
		select {
		case <-current.done:
			// A failure answers for revocationAge too: an outage costs one
			// read a second, not one per request (review s4c1b M2).
			if handler.now().Sub(current.readAt) < revocationAge {
				return current
			}
		default:
			return current
		}
	}
	read := &cachedRevocations{done: make(chan struct{}), readAt: handler.now()}
	handler.revocations = read
	go handler.readRevocations(read)
	return read
}

func (handler *handler) readRevocations(read *cachedRevocations) {
	defer close(read.done)
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	revoked, err := handler.reader.Revocations(ctx)
	if err != nil {
		read.err = err
		return
	}
	message := &flowlogv1.FlowRevocations{}
	for _, entry := range revoked.Revocations {
		networkID, device := entry.Network.Bytes(), publicid.ID(entry.Device).Bytes()
		message.Revocations = append(message.Revocations, &flowlogv1.FlowRevocations_Revocation{
			NetworkId: networkID[:], DeviceId: device[:], MachineKey: entry.MachineKey[:],
		})
	}
	read.tag, read.err = contentTag(message)
	message.GeneratedAtMs = revoked.GeneratedAt.UnixMilli()
	read.message = message
}

func (handler *handler) serveNetworks(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	var after network.ID
	if text := query.Get("after"); text != "" {
		parsed, err := network.ParseID(text)
		if err != nil || parsed.String() != text {
			handler.badRequest(response, "networks")
			return
		}
		after = parsed
	}
	limit := defaultNetworkPage
	if text := query.Get("limit"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > connectionlog.MaxReceiverNetworks {
			handler.badRequest(response, "networks")
			return
		}
		limit = parsed
	}
	ctx, cancel := context.WithTimeout(request.Context(), readTimeout)
	defer cancel()
	listed, err := handler.reader.Networks(ctx, after, limit)
	if err != nil {
		handler.unavailable(response, "networks")
		return
	}
	message := &flowlogv1.FlowNetworks{}
	for _, entry := range listed.Networks {
		workspaceID, networkID := entry.Workspace.Bytes(), entry.Network.Bytes()
		message.Networks = append(message.Networks, &flowlogv1.FlowNetworks_Network{
			WorkspaceId: workspaceID[:], NetworkId: networkID[:], Enabled: entry.Enabled,
			DestinationEtag: connectionlog.DestinationTag(entry.SettingsVersion, entry.Credential, entry.SealedVersion,
				entry.SealingKeyID, entry.ExpectedBucketOwner),
			DirectoryRevision: uint64(entry.DirectoryRevision), //nolint:gosec // a revision is positive
		})
	}
	if len(listed.Networks) == limit {
		last := listed.Networks[len(listed.Networks)-1].Network.Bytes()
		message.NextAfter = last[:]
	}
	tag, err := contentTag(message)
	if err != nil {
		handler.unavailable(response, "networks")
		return
	}
	message.GeneratedAtMs = listed.GeneratedAt.UnixMilli()
	handler.answer(response, request, "networks", tag, message)
}

var destinationReasons = map[string]flowlogv1.FlowDestination_Reason{
	connectionlog.ReasonLogging:            flowlogv1.FlowDestination_LOGGING,
	connectionlog.ReasonDisabled:           flowlogv1.FlowDestination_DISABLED,
	connectionlog.ReasonFeatureRevoked:     flowlogv1.FlowDestination_FEATURE_REVOKED,
	connectionlog.ReasonNetworkSuspended:   flowlogv1.FlowDestination_NETWORK_SUSPENDED,
	connectionlog.ReasonWorkspaceSuspended: flowlogv1.FlowDestination_WORKSPACE_SUSPENDED,
	connectionlog.ReasonNetworkDeleted:     flowlogv1.FlowDestination_NETWORK_DELETED,
	connectionlog.ReasonWorkspaceDeleted:   flowlogv1.FlowDestination_WORKSPACE_DELETED,
}

var destinationProviders = map[string]flowlogv1.FlowDestination_Provider{
	flowlog.ProviderS3: flowlogv1.FlowDestination_AWS_S3, flowlog.ProviderR2: flowlogv1.FlowDestination_CLOUDFLARE_R2,
}

func (handler *handler) serveDestination(response http.ResponseWriter, request *http.Request) {
	scope, ok := scopeOf(request.URL.Path, "destination")
	if !ok {
		handler.metrics.request("destination", "not_found")
		http.NotFound(response, request)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), readTimeout)
	defer cancel()
	destination, err := handler.reader.Destination(ctx, scope)
	if errors.Is(err, ErrNotFound) {
		handler.metrics.request("destination", "not_found")
		http.NotFound(response, request)
		return
	}
	reason, known := destinationReasons[destination.Reason]
	if err != nil || !known {
		handler.unavailable(response, "destination")
		return
	}
	message := &flowlogv1.FlowDestination{
		Reason: reason, Forwarded: destination.Forwarded,
		WindowS: uint32(destination.WindowSeconds), //nolint:gosec // 60 to 300 by the schema
		Bucket:  destination.Bucket, Region: destination.Region, Prefix: destination.Prefix,
		ExpectedBucketOwner: destination.ExpectedBucketOwner,
	}
	if destination.Sealed != nil {
		provider, known := destinationProviders[destination.Provider]
		if !known {
			handler.unavailable(response, "destination")
			return
		}
		id := publicid.ID(destination.Credential).Bytes()
		message.Credential = &flowlogv1.FlowDestination_Credential{
			CredentialId: id[:], Provider: provider, AccountId: destination.AccountID, Sealed: destination.Sealed,
			SealedVersion: uint64(destination.SealedVersion), //nolint:gosec // a version is positive
			SealingKeyId:  destination.SealingKeyID,
		}
		message.DestinationEtag = connectionlog.DestinationTag(destination.SettingsVersion, destination.Credential,
			destination.SealedVersion, destination.SealingKeyID, destination.ExpectedBucketOwner)
	}
	tag, err := contentTag(message)
	if err != nil {
		handler.unavailable(response, "destination")
		return
	}
	message.GeneratedAtMs = destination.GeneratedAt.UnixMilli()
	handler.answer(response, request, "destination", tag, message)
}

// scopeOf reads /internal/v1/flowlog/workspaces/{w}/networks/{n}/{leaf}
// with canonical IDs.
func scopeOf(path, leaf string) (network.Scope, bool) {
	segments := strings.Split(strings.TrimPrefix(path, scopedPrefix), "/")
	if len(segments) != 4 || segments[1] != "networks" || segments[3] != leaf {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[0])
	networkID, networkErr := network.ParseID(segments[2])
	if workspaceErr != nil || networkErr != nil || workspaceID.String() != segments[0] ||
		networkID.String() != segments[2] {
		return network.Scope{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, err == nil
}

func (handler *handler) badRequest(response http.ResponseWriter, route string) {
	handler.metrics.request(route, "bad_request")
	http.Error(response, "bad request", http.StatusBadRequest)
}

// answer writes message, or 304 when the client holds tag; a large answer
// goes gzipped to a client that takes it.
func (handler *handler) answer(response http.ResponseWriter, request *http.Request, route, tag string,
	message proto.Message,
) {
	if matchesTag(request.Header.Get("If-None-Match"), tag) {
		handler.answerBody(response, request, route, tag, nil)
		return
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		handler.unavailable(response, route)
		return
	}
	handler.answerBody(response, request, route, tag, body)
}

// answerBody writes an encoded answer, or 304 when the client holds tag.
func (handler *handler) answerBody(response http.ResponseWriter, request *http.Request, route, tag string,
	body []byte,
) {
	response.Header().Set("ETag", tag)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Vary", "Accept-Encoding")
	if matchesTag(request.Header.Get("If-None-Match"), tag) {
		handler.metrics.request(route, "not_modified")
		response.WriteHeader(http.StatusNotModified)
		return
	}
	if len(body) > gzipAbove && acceptsGzip(request.Header.Get("Accept-Encoding")) {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(body); err == nil && writer.Close() == nil {
			body = compressed.Bytes()
			response.Header().Set("Content-Encoding", "gzip")
			// Another encoding of the same content: a weak tag (RFC 9110
			// §8.8.3), which If-None-Match compares weakly anyway.
			response.Header().Set("ETag", "W/"+tag)
		}
	}
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
	handler.metrics.request(route, "ok")
	handler.metrics.responseBytes(route, len(body))
}

func acceptsGzip(header string) bool {
	for _, coding := range strings.Split(header, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(coding), ";")
		if strings.EqualFold(name, "gzip") {
			return true
		}
	}
	return false
}

// matchesTag compares If-None-Match weakly (RFC 9110 §13.1.2), "*" too.
func matchesTag(header, tag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == tag {
			return true
		}
	}
	return false
}

// routeOf names a path for metrics and routing, never with an ID in it.
func routeOf(path string) string {
	switch {
	case path == keysPath:
		return "keys"
	case path == revocationsPath:
		return "revocations"
	case path == networksPath:
		return "networks"
	case path == statusPath:
		return "status"
	case strings.HasPrefix(path, scopedPrefix) && strings.HasSuffix(path, "/destination"):
		return "destination"
	case strings.HasPrefix(path, scopedPrefix) && strings.HasSuffix(path, "/directory"):
		return "directory"
	}
	return "other"
}
