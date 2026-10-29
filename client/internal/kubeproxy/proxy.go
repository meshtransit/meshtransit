package kubeproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubeevent"
	"meshtransit.net/client/internal/kubereq"
)

const (
	// ownerChangeHold: a Device that changed owner this recently uses no
	// privileged group (K1 §5.4, Q58).
	ownerChangeHold = 7 * 24 * time.Hour
	// maximumImpersonatedGroups bounds the groups one request may name.
	maximumImpersonatedGroups = 8
	// maximumImpersonated bounds what the intent records of them.
	maximumImpersonated = 253
	// maximumAgent bounds the client's User-Agent kept.
	maximumAgent = 64
	// workspaceOwner keys the tokens of a Device of the Workspace.
	workspaceOwner = "workspace"
)

// Server is the proxy.
type Server struct {
	options Options
	groups  map[string]Group
	// order is the groups a request without one may use: the default,
	// then the others not privileged, weakest first as configured.
	order    []Group
	backend  *url.URL
	reverse  *httputil.ReverseProxy
	sessions *registry
}

// New makes a proxy; Serve serves it.
func New(options Options) (*Server, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	backend, _ := url.Parse(options.Backend)
	backend.Path = ""
	server := &Server{options: options, groups: map[string]Group{}, backend: backend, sessions: newRegistry()}
	transports, err := newTransports(options.BackendCA, server.remint)
	if err != nil {
		return nil, err
	}
	for _, group := range options.Groups {
		server.groups[group.Name] = group
		if group.Default {
			server.order = append([]Group{group}, server.order...)
		} else if !group.Privileged {
			server.order = append(server.order, group)
		}
	}
	server.reverse = &httputil.ReverseProxy{
		Rewrite:        rewrite,
		Transport:      transports,
		FlushInterval:  -1,
		ModifyResponse: server.answered,
		// A copy a cut or a client ends, at debug: not an event.
		ErrorLog: slog.NewLogLogger(options.Logger.Handler(), slog.LevelDebug),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			carried, _ := r.Context().Value(planKey{}).(*plan)
			if reason := cutReasonOf(r.Context()); reason != "" {
				// Cut by the sweep before the API server answered: it may
				// have reached it. The client hears why, never an empty 200
				// (review b6a H1).
				if carried != nil {
					carried.status.Store(statusClientGone)
					server.cutAnswer(w, carried.device, carried.group, reason, carried.typeA)
				}
				return
			}
			if errors.Is(err, context.Canceled) {
				// The client left: the request may have reached the API
				// server, so it is reported answered, not "not forwarded".
				if carried != nil {
					carried.status.Store(statusClientGone)
				}
				options.Logger.Debug("kube request cancelled by the client")
				return
			}
			if carried != nil {
				carried.status.Store(http.StatusBadGateway)
			}
			options.Logger.Warn("kube API server unreachable", "error_code", "kubernetes_api_unreachable",
				"error", err)
			refuse(w, http.StatusBadGateway, "the gateway could not reach the API server", 0)
		},
	}
	return server, nil
}

// TLSConfig is the listener's: TLS 1.3, h2 and http/1.1, the replica's
// certificate taken at each handshake, an SNI among its names, no session
// tickets (K1b design §3).
func (server *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// A source no Device of the map holds gets no certificate, so
			// not even the cluster's name (K1b design §4; re-review b5a).
			if conn, ok := hello.Conn.(*identified); ok {
				if _, _, known := conn.bind(server.options.Peer); !known {
					return nil, errors.New("kubeproxy: a source no Device holds")
				}
			}
			certificate, ok := server.options.Certificate()
			if !ok || certificate.Leaf == nil {
				return nil, errors.New("kubeproxy: no valid certificate")
			}
			if !servedName(certificate, hello.ServerName) {
				return nil, errors.New("kubeproxy: an unknown server name")
			}
			return certificate, nil
		},
	}
}

// Serve serves kubectl on a listener on the mesh address until it closes.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	served := &http.Server{
		Handler:           server,
		TLSConfig:         server.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ConnContext:       withIdentity,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		// Failed handshakes and the like, at debug: a scan is not an event.
		ErrorLog: slog.NewLogLogger(server.options.Logger.Handler(), slog.LevelDebug),
	}
	// Cancelling ctx also ends hijacked connections (exec, port-forward),
	// which Close leaves open (review b5a L3).
	stop := context.AfterFunc(ctx, func() { _ = served.Close() })
	defer stop()
	err := served.ServeTLS(identifying{Listener: listener}, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// plan is what a request is forwarded with.
type plan struct {
	out          *url.URL
	token        Bearer
	auditID      [16]byte
	source       string
	device       string
	group        Group
	typeA        bool // Core recorded it
	version      string
	agent        string
	impersonate  http.Header // the Impersonate-* kept, for a group allowed
	status       atomic.Int64
	refusedToken bool
	// remint gives a new token once the API server refused this one; nil
	// for a request with a body, which cannot be sent again.
	remint func() (Bearer, error)
}

// statusClientGone is reported for a request whose client left before the
// API server answered it.
const statusClientGone = 499

type planKey struct{}

// allowedMethods are the methods forwarded; OPTIONS is answered here.
var allowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete}

// ServeHTTP checks a request and forwards it (K1b design §4–§7).
func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	who, err := identityOf(r.Context())
	if err != nil {
		refuse(w, http.StatusInternalServerError, "the gateway lost the request's connection", 0)
		return
	}
	// The connection's Device first: nothing is counted against a Device
	// whose address moved (review b5a L1).
	deviceID, key, known := who.bind(server.options.Peer)
	peer, ok := server.options.Peer(who.source)
	if !known || !ok || peer.DeviceID != deviceID || peer.Key != key {
		// The address is another Device's now, or no one's (K1-I4). Closing
		// the connection ends its other HTTP/2 streams too, as it must.
		_ = who.Conn.Close()
		panic(http.ErrAbortHandler)
	}
	escaped := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodOptions:
		refuse(w, http.StatusMethodNotAllowed, "OPTIONS is not served", 0)
		return
	case !slices.Contains(allowedMethods, r.Method):
		server.deny(w, peer.DeviceID, "other", http.StatusMethodNotAllowed, "method not allowed", 0)
		return
	case kubereq.CheckPath(escaped) != nil:
		server.deny(w, peer.DeviceID, "other", http.StatusBadRequest,
			"the gateway forwards only plain paths: no escapes, empty or dot segments", 0)
		return
	case !server.servedHost(r.Host):
		server.deny(w, peer.DeviceID, "other", http.StatusBadRequest, "the request names another host", 0)
		return
	case !allowedUpgrade(r.Header):
		server.deny(w, peer.DeviceID, "other", http.StatusBadRequest,
			"only WebSocket and SPDY/3.1 upgrades are served", 0)
		return
	case server.stale():
		server.deny(w, peer.DeviceID, "stale", http.StatusServiceUnavailable,
			"the gateway has no current map from MeshTransit", time.Second)
		return
	}
	if reason := browserRequest(r); reason != "" {
		server.deny(w, peer.DeviceID, "forbidden", http.StatusForbidden, reason, 0)
		return
	}
	if escaped == "/mt/v1/whoami" {
		server.whoami(w, r, peer)
		return
	}
	named, rest, ok := kubereq.SplitGroup(escaped)
	if !ok {
		refuse(w, http.StatusNotFound, "not a path of the gateway", 0)
		return
	}
	group, reason := server.choose(peer, named)
	if reason != "" {
		server.deny(w, peer.DeviceID, "not_granted", http.StatusForbidden, reason, 0)
		return
	}
	if selfSubjectReview(r.Method, rest) {
		server.selfReview(w, rest, peer, group)
		return
	}
	if reason := connectionNamesCredentials(r.Header); reason != "" {
		server.deny(w, peer.DeviceID, "other", http.StatusBadRequest, reason, 0)
		return
	}
	impersonate, impersonated, code, reason := server.impersonation(r.Header, group)
	if reason != "" {
		server.deny(w, peer.DeviceID, "forbidden", code, reason, 0)
		return
	}
	out := server.outbound(rest, r.URL.RawQuery)
	class, info := kubereq.Classify(kubereq.Request{Method: r.Method, URL: out, Header: r.Header},
		kubereq.Options{Privileged: group.Privileged, Impersonating: len(impersonate) > 0,
			SecretResources: server.options.SecretResources})
	// The session is registered, then checked again: a map that changed
	// since choose is seen here, one that changes after by the sweep
	// (K1b design §8).
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	held := &session{device: peer.DeviceID, key: peer.Key, source: who.source, group: group,
		kind: sessionKind(r, out, info), impersonating: len(impersonate) > 0, cancel: cancel}
	if held.kind == kindUpgrade && r.ProtoMajor == 1 {
		held.close = func() { _ = who.Conn.Close() }
	}
	done := server.sessions.add(held)
	defer done()
	if ended := server.ended(held); ended != "" {
		server.cutAnswer(w, peer.DeviceID, group, ended, false)
		return
	}
	server.forward(w, r.WithContext(ctx), forwarding{who: who, peer: peer, group: group, out: out, class: class,
		info: info, impersonate: impersonate, impersonated: impersonated, started: started, session: held})
}

// sessionKind is a request's kind for the registry.
func sessionKind(r *http.Request, out *url.URL, info kubereq.Info) string {
	switch {
	case r.Header.Get("Upgrade") != "":
		return kindUpgrade
	case info.Verb == "watch":
		return kindWatch
	case info.Subresource == "log" && followed(out.Query().Get("follow")):
		return kindStream
	}
	return kindRequest
}

// followed reads follow= as the API server does, a bool (re-review b6a L4).
func followed(value string) bool {
	follow, err := strconv.ParseBool(value)
	return err == nil && follow
}

// forwarding is one request on its way to the API server.
type forwarding struct {
	who          *identified
	peer         Peer
	group        Group
	out          *url.URL
	class        kubereq.Class
	info         kubereq.Info
	impersonate  http.Header
	impersonated string
	started      time.Time
	session      *session
}

// forward mints the token, has Core record a type A operation, and
// forwards; only a recorded type A operation goes on (K1-I10). Its outcome,
// a refused token and its log line follow in a defer: a response whose copy
// breaks (a watch the client ends) panics out of the ReverseProxy (review
// b5a H1).
func (server *Server) forward(w http.ResponseWriter, r *http.Request, request forwarding) {
	owner := ownerOf(request.peer)
	token, err := server.options.Tokens.For(r.Context(), request.peer.DeviceID, owner, request.group.Name)
	if reason := cutReasonOf(r.Context()); err != nil && reason != "" {
		// Cut while minting: not a minter fault (review b6a L2).
		server.cutAnswer(w, request.peer.DeviceID, request.group, reason, false)
		return
	}
	if err != nil {
		server.options.Logger.Warn("Kubernetes token not minted", "error_code", "kubernetes_token_unavailable",
			"group", request.group.Name, "error", err)
		refuse(w, http.StatusServiceUnavailable, "the gateway could not get a token for group "+request.group.Name,
			time.Second)
		return
	}
	carried := &plan{out: request.out, token: token, source: request.who.source.String(),
		device: request.peer.DeviceID, group: request.group, agent: agentOf(r.Header.Get("User-Agent")),
		impersonate: request.impersonate,
		version:     server.options.Version}
	if r.ContentLength == 0 && !request.class.TypeA() {
		// A request without a body can be sent again with a new token once
		// (review b5a M4). Not a type A one: Core's record names the token
		// it goes out with, so a refused one is forgotten and the 401
		// returned (re-review b5a M-a).
		carried.remint = func() (Bearer, error) {
			server.options.Tokens.Forget(request.peer.DeviceID, owner, request.group.Name, carried.token)
			return server.options.Tokens.For(r.Context(), request.peer.DeviceID, owner, request.group.Name)
		}
	}
	if request.class.TypeA() {
		answer := server.options.Records.Record(r.Context(), request.peer.DeviceID, controlplane.KubeAuditIntent{
			Peer: request.peer.DeviceID, Groups: []string{request.group.Name}, Class: string(request.class),
			Verb: request.info.Verb, APIGroup: request.info.APIGroup, Resource: request.info.Resource,
			Subresource: request.info.Subresource, Namespace: request.info.Namespace, Name: request.info.Name,
			Impersonated: request.impersonated, TokenID: token.ID(),
		})
		if !answer.Recorded {
			if reason := cutReasonOf(r.Context()); reason != "" {
				server.cutAnswer(w, request.peer.DeviceID, request.group, reason, false)
				return
			}
			server.unrecorded(w, request.peer.DeviceID, answer)
			return
		}
		carried.auditID, carried.typeA = answer.AuditID, true
		if request.group.Privileged && !server.announce(r.Context(), request, owner, carried.auditID) {
			server.options.Records.Finished(carried.auditID, 0, time.Since(request.started))
			if reason := cutReasonOf(r.Context()); reason != "" {
				server.cutAnswer(w, request.peer.DeviceID, request.group, reason, true)
				return
			}
			refuse(w, http.StatusServiceUnavailable, "the gateway could not record the privileged session in "+
				"the cluster", time.Second)
			return
		}
	} else if carried.auditID, err = newAuditID(); err != nil {
		refuse(w, http.StatusInternalServerError, "the gateway could not name the request", 0)
		return
	}
	if request.session != nil {
		server.sessions.setAuditID(request.session, carried.auditID)
	}
	defer func() {
		status := int(carried.status.Load())
		if request.class.TypeA() {
			server.options.Records.Finished(carried.auditID, status, time.Since(request.started))
		}
		if carried.refusedToken {
			server.options.Tokens.Forget(request.peer.DeviceID, owner, request.group.Name, carried.token)
		}
		server.options.Logger.Info("kube request", "audit_id", formatAuditID(carried.auditID),
			"device_id", request.peer.DeviceID, "group", request.group.Name, "class", string(request.class),
			"verb", request.info.Verb, "resource", request.info.Resource, "subresource", request.info.Subresource,
			"namespace", request.info.Namespace, "name", request.info.Name, "status", status,
			"duration_ms", time.Since(request.started).Milliseconds())
	}()
	server.reverse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), planKey{}, carried)))
}

// announce has the cluster record a privileged group's use; false when the
// first use of its window could not be, which refuses it (K1b design §4).
func (server *Server) announce(ctx context.Context, request forwarding, owner string, auditID [16]byte) bool {
	counted, err := server.options.Events.Privileged(ctx, kubeevent.Use{Device: request.peer.DeviceID,
		DeviceName: request.peer.Name, Owner: owner, Group: request.group.Name,
		Source: request.who.source.String(), AuditID: formatAuditID(auditID)})
	if err != nil && cutReasonOf(ctx) == "" {
		server.options.Logger.Error("Kubernetes privileged session Event failed", "error_code",
			"kubernetes_privileged_event_failed", "device_id", request.peer.DeviceID, "group", request.group.Name,
			"counted", counted, "error", err)
	}
	return counted
}

// remint is the transport's way back to a request's plan for a new token.
func (server *Server) remint(request *http.Request) (Bearer, bool) {
	carried, _ := request.Context().Value(planKey{}).(*plan)
	if carried == nil || carried.remint == nil {
		return nil, false
	}
	token, err := carried.remint()
	if err != nil {
		return nil, false
	}
	carried.token, carried.remint = token, nil
	return token, true
}

// unrecorded answers a type A operation Core did not record.
func (server *Server) unrecorded(w http.ResponseWriter, device string, answer kubeaudit.Answer) {
	switch {
	case answer.Err != nil:
		refuse(w, http.StatusServiceUnavailable,
			"MeshTransit did not record the operation in time; it was not sent to the API server", time.Second)
	case answer.Refused == "limited":
		refuse(w, http.StatusTooManyRequests, "too many operations; try again shortly", answer.RetryAfter)
	case answer.Refused == "device" || answer.Refused == "not_granted":
		refuse(w, http.StatusForbidden, "MeshTransit refused the operation: the Device's access changed", 0)
	case answer.Refused == "invalid" || answer.Refused == "conflict":
		server.options.Logger.Error("Kubernetes operation refused by Core", "error_code",
			"kubernetes_operation_refused", "reason", answer.Refused, "device_id", device)
		refuse(w, http.StatusForbidden, "MeshTransit refused the operation", 0)
	default:
		refuse(w, http.StatusServiceUnavailable, "MeshTransit could not record the operation now",
			max(answer.RetryAfter, time.Second))
	}
}

// deny answers a request the gateway refuses itself: a type B count.
func (server *Server) deny(w http.ResponseWriter, device, reason string, code int, message string,
	wait time.Duration,
) {
	server.options.Records.Denied(device, reason)
	refuse(w, code, message, wait)
}

// stale reports a map Core has not confirmed within StaleAfter.
func (server *Server) stale() bool {
	fresh := server.options.MapFreshAt()
	return fresh.IsZero() || time.Since(fresh) > server.options.StaleAfter
}

// choose picks the request's group: the one named, which the peer must
// hold; else the default, or the first weakest group the peer holds and
// that is on. A privileged group needs its principal on a Device that kept
// its owner a week (K1-I7).
func (server *Server) choose(peer Peer, named string) (Group, string) {
	held := peer.Access.GroupsAt(server.options.CoreNow())
	if named != "" {
		group, configured := server.groups[named]
		switch {
		case !configured || !slices.Contains(held, named):
			return Group{}, fmt.Sprintf("Device %s holds no Kubernetes group %q in cluster %s", peer.Name, named,
				server.options.Cluster)
		case !server.options.Verdict(named).Enabled:
			return Group{}, fmt.Sprintf("group %q is turned off by the gateway: %s", named,
				server.options.Verdict(named).Reason)
		}
		if group.Privileged {
			if reason := server.privileged(peer, group); reason != "" {
				return Group{}, reason
			}
		}
		return group, ""
	}
	off := ""
	for _, group := range server.order {
		if !slices.Contains(held, group.Name) {
			continue
		}
		verdict := server.options.Verdict(group.Name)
		if verdict.Enabled {
			return group, ""
		}
		if off == "" {
			off = fmt.Sprintf("group %q is turned off by the gateway: %s", group.Name, verdict.Reason)
		}
	}
	if off != "" {
		// Say why the group the Device would use is off, not that it holds
		// none (kind demo b5b).
		return Group{}, off
	}
	if len(held) > 0 {
		return Group{}, fmt.Sprintf("Device %s holds only groups used by name in cluster %s; use the context "+
			"for one of: %s", peer.Name, server.options.Cluster, strings.Join(held, ", "))
	}
	return Group{}, fmt.Sprintf("Device %s has no Kubernetes access to cluster %s; ask an admin for a "+
		"Kubernetes access rule", peer.Name, server.options.Cluster)
}

// privileged checks a privileged group's principal and owner age.
func (server *Server) privileged(peer Peer, group Group) string {
	switch {
	case peer.Access == nil || peer.Access.OwnerRef == "":
		return fmt.Sprintf("group %q is for listed people only, not a Device of the Workspace", group.Name)
	case !slices.Contains(group.AllowedPrincipals, peer.Access.OwnerRef):
		return fmt.Sprintf("group %q is for listed people only", group.Name)
	case !peer.Access.OwnerChangedAt.IsZero() &&
		server.options.CoreNow().Sub(peer.Access.OwnerChangedAt) < ownerChangeHold:
		return fmt.Sprintf("group %q is not used on a Device that changed owner in the last 7 days", group.Name)
	}
	return ""
}

// impersonation keeps Impersonate-User and Impersonate-Group for a group
// allowed them, refusing system: values; other groups have them dropped
// (K1-I3). It returns what to forward and what the intent records.
func (server *Server) impersonation(header http.Header, group Group) (http.Header, string, int, string) {
	users, groups := header.Values("Impersonate-User"), header.Values("Impersonate-Group")
	if len(users)+len(groups) == 0 || !group.AllowImpersonation ||
		!server.options.Verdict(group.Name).Impersonation {
		return nil, "", 0, ""
	}
	if len(users) > 1 || len(groups) > maximumImpersonatedGroups {
		return nil, "", http.StatusBadRequest, "too many impersonated names"
	}
	kept := http.Header{}
	names := make([]string, 0, len(users)+len(groups))
	for _, value := range append(slices.Clone(users), groups...) {
		switch {
		case value == "" || strings.Contains(value, ","):
			return nil, "", http.StatusBadRequest, "an impersonated name is empty or holds a comma"
		case strings.HasPrefix(value, "system:"):
			return nil, "", http.StatusForbidden, "impersonating system: names is not allowed"
		}
		names = append(names, value)
	}
	for _, user := range users {
		kept.Add("Impersonate-User", user)
	}
	for _, name := range groups {
		kept.Add("Impersonate-Group", name)
	}
	impersonated := strings.Join(names, ",")
	if len(impersonated) > maximumImpersonated {
		return nil, "", http.StatusBadRequest, "impersonated names too long"
	}
	return kept, impersonated, 0, ""
}

// outbound is the URL forwarded: the API server, the path, and the query
// as Go would forward it, so what is classified is what is sent (§5).
func (server *Server) outbound(path, query string) *url.URL {
	out := *server.backend
	out.Path, out.RawPath = path, ""
	if values, err := url.ParseQuery(query); err != nil {
		out.RawQuery = values.Encode()
	} else {
		out.RawQuery = query
	}
	return &out
}

// rewrite builds the forwarded request: the planned URL, no client
// credential, the gateway's own headers (K1-I3, §6).
func rewrite(proxied *httputil.ProxyRequest) {
	carried, _ := proxied.In.Context().Value(planKey{}).(*plan)
	if carried == nil {
		return
	}
	out := *carried.out
	proxied.Out.URL, proxied.Out.Host = &out, ""
	stripCredentials(proxied.Out.Header)
	proxied.Out.Trailer = nil
	for name, values := range carried.impersonate {
		proxied.Out.Header[name] = slices.Clone(values)
	}
	proxied.Out.Header.Set("Authorization", "Bearer "+carried.token.Value())
	proxied.Out.Header.Set("Audit-Id", formatAuditID(carried.auditID))
	proxied.Out.Header.Set("X-Forwarded-For", carried.source)
	proxied.Out.Header.Set("User-Agent", "meshgw/"+carried.version+" device/"+carried.device+
		" (client: "+carried.agent+")")
}

// answered records the API server's status; a 401 forgets the token.
func (server *Server) answered(response *http.Response) error {
	carried, _ := response.Request.Context().Value(planKey{}).(*plan)
	if carried != nil {
		carried.status.Store(int64(response.StatusCode))
		carried.refusedToken = response.StatusCode == http.StatusUnauthorized
	}
	return nil
}

// ownerOf keys a Device's tokens by its owner.
func ownerOf(peer Peer) string {
	if peer.Access == nil || peer.Access.OwnerRef == "" {
		return workspaceOwner
	}
	return peer.Access.OwnerRef
}

// agentOf keeps a client's User-Agent's printable ASCII, bounded.
func agentOf(agent string) string {
	cleaned := strings.Map(func(character rune) rune {
		if character < ' ' || character > '~' || character == '(' || character == ')' {
			return -1
		}
		return character
	}, agent)
	return cleaned[:min(len(cleaned), maximumAgent)]
}

// newAuditID is a UUIDv7 for a request that is not type A.
func newAuditID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[6:]); err != nil {
		return id, err
	}
	var millis [8]byte
	binary.BigEndian.PutUint64(millis[:], uint64(time.Now().UnixMilli())) //nolint:gosec // after 1970
	copy(id[:6], millis[2:])
	id[6] = 0x70 | id[6]&0x0f
	id[8] = 0x80 | id[8]&0x3f
	return id, nil
}

// formatAuditID is an ID as a UUID.
func formatAuditID(id [16]byte) string {
	text := hex.EncodeToString(id[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

// newTransports are the API server's: HTTP/2 for requests, HTTP/1.1 for
// upgrades (SPDY and WebSocket), the cluster's CA, no proxy, bounded dials
// and handshakes (review b5a M5). A 401 to a request without a body is
// sent once more with a new token.
func newTransports(caFile string, remint func(*http.Request) (Bearer, bool)) (http.RoundTripper, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("kubeproxy: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("kubeproxy: the cluster CA file holds no certificate")
	}
	secured := func() *tls.Config { return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12} }
	dial := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	requests := &http.Transport{TLSClientConfig: secured(), ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second,
		DialContext: dial, TLSHandshakeTimeout: 10 * time.Second,
		HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: 128 << 10, SendPingTimeout: 30 * time.Second,
			PingTimeout: 15 * time.Second}}
	upgrades := &http.Transport{TLSClientConfig: secured(), IdleConnTimeout: 90 * time.Second,
		DialContext: dial, TLSHandshakeTimeout: 10 * time.Second,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return roundTrips{requests: requests, upgrades: upgrades, remint: remint}, nil
}

type roundTrips struct {
	requests, upgrades *http.Transport
	remint             func(*http.Request) (Bearer, bool)
}

func (trips roundTrips) RoundTrip(request *http.Request) (*http.Response, error) {
	transport := trips.requests
	if request.Header.Get("Upgrade") != "" {
		transport = trips.upgrades
	}
	response, err := transport.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	token, ok := trips.remint(request)
	if !ok {
		return response, nil
	}
	_ = response.Body.Close()
	again := request.Clone(request.Context())
	again.Header.Set("Authorization", "Bearer "+token.Value())
	return transport.RoundTrip(again)
}

// servedName reports a server name among the certificate's, as clients
// may send it: any case, a trailing dot (review b5a L4).
func servedName(certificate *tls.Certificate, name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name != "" && slices.ContainsFunc(certificate.Leaf.DNSNames, func(served string) bool {
		return strings.EqualFold(served, name)
	})
}

// servedHost reports a request's Host among the certificate's names (K1b
// design §3, review b5a M3).
func (server *Server) servedHost(host string) bool {
	certificate, ok := server.options.Certificate()
	if !ok || certificate.Leaf == nil {
		return false
	}
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return servedName(certificate, host)
}

// allowedUpgrade reports no upgrade, or one to WebSocket or SPDY/3.1 (K1b
// design §5).
func allowedUpgrade(header http.Header) bool {
	for _, value := range header.Values("Upgrade") {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.EqualFold(protocol, "websocket") && protocol != "SPDY/3.1" {
				return false
			}
		}
	}
	return true
}
