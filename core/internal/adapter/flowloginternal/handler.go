package flowloginternal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/shared/flowlog"
)

const (
	keysPath = "/internal/v1/flowlog/keys"
	// contentType is protobuf; the receiver refuses unknown fields.
	contentType = "application/x-protobuf"
	// The receiver polls a handful of paths every few seconds per replica.
	requestRate  = 50
	requestBurst = 200
)

// handler routes the internal API. It answers only GET, and every answer
// carries an ETag of its content so a poll that finds nothing new is 304.
type handler struct {
	keys    *flowlogv1.FlowSigningKeys
	keysTag string
	limiter *rate.Limiter
	metrics *Metrics
	now     func() time.Time
}

func newHandler(tokenKeys []TokenKey, metrics *Metrics, now func() time.Time) (*handler, error) {
	keys := &flowlogv1.FlowSigningKeys{}
	current := 0
	for _, key := range tokenKeys {
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
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(keys)
	if err != nil {
		return nil, ErrInvalidServer
	}
	return &handler{
		keys: keys, keysTag: entityTag(content), limiter: rate.NewLimiter(requestRate, requestBurst),
		metrics: metrics, now: now,
	}, nil
}

var keyStates = map[string]flowlogv1.FlowSigningKeys_State{
	"current": flowlogv1.FlowSigningKeys_CURRENT, "next": flowlogv1.FlowSigningKeys_NEXT,
	"retiring": flowlogv1.FlowSigningKeys_RETIRING, "revoked": flowlogv1.FlowSigningKeys_REVOKED,
}

// entityTag is a strong ETag of the answer's content, apart from its time.
func entityTag(content []byte) string {
	digest := sha256.Sum256(content)
	return `"` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`
}

func (handler *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	route := routeOf(request.URL.Path)
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
	switch request.URL.Path {
	case keysPath:
		keys := proto.Clone(handler.keys).(*flowlogv1.FlowSigningKeys) //nolint:forcetypeassert // Clone keeps the type
		keys.GeneratedAtMs = handler.now().UnixMilli()
		handler.answer(response, request, route, handler.keysTag, keys)
	default:
		handler.metrics.request(route, "not_found")
		http.NotFound(response, request)
	}
}

// answer writes message, or 304 when the client holds tag.
func (handler *handler) answer(response http.ResponseWriter, request *http.Request, route, tag string,
	message proto.Message,
) {
	response.Header().Set("ETag", tag)
	response.Header().Set("Cache-Control", "no-store")
	if matchesTag(request.Header.Get("If-None-Match"), tag) {
		handler.metrics.request(route, "not_modified")
		response.WriteHeader(http.StatusNotModified)
		return
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		handler.metrics.request(route, "error")
		http.Error(response, "internal error", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
	handler.metrics.request(route, "ok")
	handler.metrics.responseBytes(route, len(body))
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

// routeOf names a path for metrics, never with an ID in it.
func routeOf(path string) string {
	if path == keysPath {
		return "keys"
	}
	return "other"
}
