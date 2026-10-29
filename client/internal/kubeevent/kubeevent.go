// Package kubeevent records each use of a privileged Kubernetes group as an
// Event in the gateway's namespace: a signal on the cluster's side that
// does not depend on MeshTransit Core (K1b design §4, K1 §10.1).
package kubeevent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Reason is the Events' reason.
	Reason = "MeshPrivilegedSession"
	// callTimeout bounds one call to the API server.
	callTimeout = 5 * time.Second
	// maximumAnswer bounds what is read of an answer.
	maximumAnswer = 64 << 10
	// maximumKept bounds the (Device, group) windows remembered.
	maximumKept = 10000
)

// Use is one use of a privileged group.
type Use struct {
	// Device and DeviceName name the Device; Owner its owner's reference.
	Device, DeviceName, Owner string
	Group                     string
	// Source is the Device's mesh address; AuditID Core's record.
	Source, AuditID string
}

// Options configure a recorder.
type Options struct {
	// Server is the API server's https URL, CAFile its CA, TokenFile the
	// gateway's own token, read for every call.
	Server, CAFile, TokenFile string
	// Namespace is the gateway's; Instance its pod, reporting the Events.
	Namespace, Instance string
	// Window gathers the uses of one (Device, group) into one Event.
	Window time.Duration
	// Now is the clock; nil: time.Now.
	Now func() time.Time
	// Logger hears of counts that could not be raised; nil: none.
	Logger *slog.Logger
}

// Recorder creates the Events.
type Recorder struct {
	options Options
	client  *http.Client
	events  string // the namespace's events URL

	mu      sync.Mutex
	windows map[key]*window
}

type key struct{ device, group string }

// window is one (Device, group)'s Event: made at its first use, its count
// raised after, until Window passes. Only the make waits on the API
// server; raising the count runs apart, one call at a time with the latest
// count (review b6a M3).
type window struct {
	mu    sync.Mutex
	name  string // empty until the Event exists
	first time.Time
	count int
	// making is closed when a make in progress ends.
	making chan struct{}
	// raising: a raise runs; dirty: the count moved since it began.
	raising, dirty bool
}

// errNotFound: the Event is gone (deleted), so the next use makes a new one.
var errNotFound = errors.New("kubeevent: the Event is gone")

// New makes a recorder.
func New(options Options) (*Recorder, error) {
	parsed, err := url.Parse(options.Server)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		strings.Trim(parsed.Path, "/") != "" || options.TokenFile == "" || options.Namespace == "" ||
		options.Instance == "" || options.Window < time.Minute {
		return nil, errors.New("kubeevent: invalid options")
	}
	pem, err := os.ReadFile(options.CAFile)
	if err != nil {
		return nil, fmt.Errorf("kubeevent: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("kubeevent: the cluster CA file holds no certificate")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second}
	return &Recorder{
		options: options,
		client: &http.Client{Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		events:  strings.TrimSuffix(options.Server, "/") + "/api/v1/namespaces/" + options.Namespace + "/events",
		windows: map[key]*window{},
	}, nil
}

// Privileged records a use. The first use in a window must make its Event,
// or the use is refused (an error): the cluster always hears of a
// privileged session. Later uses raise the count apart from the request.
func (recorder *Recorder) Privileged(ctx context.Context, use Use) (counted bool, err error) {
	held := recorder.window(key{use.Device, use.Group})
	held.mu.Lock()
	for {
		now := recorder.options.Now()
		if held.name != "" && now.Sub(held.first) < recorder.options.Window {
			held.count++
			if held.raising {
				held.dirty = true
			} else {
				held.raising = true
				go recorder.raiseAll(held)
			}
			held.mu.Unlock()
			return true, nil
		}
		if held.making == nil {
			break
		}
		// Another use makes the Event: wait for it, as long as this one
		// is wanted.
		making := held.making
		held.mu.Unlock()
		select {
		case <-making:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		held.mu.Lock()
	}
	making := make(chan struct{})
	held.making = making
	held.mu.Unlock()
	now := recorder.options.Now()
	name, err := recorder.create(ctx, use, now)
	held.mu.Lock()
	defer held.mu.Unlock()
	held.making = nil
	close(making)
	if err != nil {
		return false, err
	}
	held.name, held.first, held.count = name, now, 1
	return true, nil
}

// raiseAll sets the Event's count until it no longer moves. An Event
// someone deleted is made again by the next use (review b6a M4).
func (recorder *Recorder) raiseAll(held *window) {
	for {
		held.mu.Lock()
		name, count := held.name, held.count
		held.dirty = false
		held.mu.Unlock()
		err := recorder.raise(context.Background(), name, count, recorder.options.Now())
		held.mu.Lock()
		if errors.Is(err, errNotFound) && held.name == name {
			held.name = ""
		}
		// Uses since: raise again, with the window's Event, which may be a
		// new one made meanwhile (re-review b6a L1).
		again := held.dirty && held.name != "" && (held.name != name || err == nil)
		if !again {
			held.raising = false
		}
		held.mu.Unlock()
		if err != nil && recorder.options.Logger != nil {
			recorder.options.Logger.Warn("Kubernetes privileged session Event count not raised", "error_code",
				"kubernetes_privileged_event_count_failed", "event", name, "error", err)
		}
		if !again {
			return
		}
	}
}

// window returns a (Device, group)'s window, dropping expired ones when
// many are kept.
func (recorder *Recorder) window(id key) *window {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if held, ok := recorder.windows[id]; ok {
		return held
	}
	if len(recorder.windows) >= maximumKept {
		now := recorder.options.Now()
		for kept, held := range recorder.windows {
			if held.mu.TryLock() {
				expired := held.making == nil && !held.raising && now.Sub(held.first) >= recorder.options.Window
				held.mu.Unlock()
				if expired {
					delete(recorder.windows, kept)
				}
			}
		}
	}
	held := &window{}
	if len(recorder.windows) < maximumKept {
		// Past the bound a window is not kept: each use makes its own
		// Event, which still tells the cluster (review b6a L6).
		recorder.windows[id] = held
	}
	return held
}

// event is the part of a core/v1 Event the recorder writes.
type event struct {
	APIVersion         string         `json:"apiVersion"`
	Kind               string         `json:"kind"`
	Metadata           eventMeta      `json:"metadata"`
	InvolvedObject     objectRef      `json:"involvedObject"`
	Reason             string         `json:"reason"`
	Message            string         `json:"message"`
	Type               string         `json:"type"`
	Count              int            `json:"count"`
	FirstTimestamp     string         `json:"firstTimestamp"`
	LastTimestamp      string         `json:"lastTimestamp"`
	Source             map[string]any `json:"source"`
	ReportingComponent string         `json:"reportingComponent"`
	ReportingInstance  string         `json:"reportingInstance"`
}

type eventMeta struct {
	GenerateName string            `json:"generateName,omitempty"`
	Namespace    string            `json:"namespace"`
	Labels       map[string]string `json:"labels,omitempty"`
}

type objectRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// create makes the window's Event, on the group's ServiceAccount.
func (recorder *Recorder) create(ctx context.Context, use Use, now time.Time) (string, error) {
	stamp := now.UTC().Format(time.RFC3339)
	body, err := json.Marshal(event{
		APIVersion: "v1", Kind: "Event",
		Metadata: eventMeta{GenerateName: "meshgw-privileged-", Namespace: recorder.options.Namespace,
			Labels: map[string]string{"app.kubernetes.io/name": "meshgw", "meshtransit.net/group": use.Group}},
		InvolvedObject: objectRef{APIVersion: "v1", Kind: "ServiceAccount", Namespace: recorder.options.Namespace,
			Name: "mt-" + use.Group},
		Reason: Reason, Type: "Warning",
		Message: fmt.Sprintf("Device %s (%s) of owner %s uses privileged group %s from %s; first audit_id %s",
			use.Device, use.DeviceName, ownerText(use.Owner), use.Group, use.Source, use.AuditID),
		Count: 1, FirstTimestamp: stamp, LastTimestamp: stamp,
		Source:             map[string]any{"component": "meshgw"},
		ReportingComponent: "meshtransit.net/meshgw", ReportingInstance: recorder.options.Instance,
	})
	if err != nil {
		return "", err
	}
	payload, err := recorder.call(ctx, http.MethodPost, recorder.events, "application/json", body, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var made struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &made); err != nil || made.Metadata.Name == "" {
		return "", errors.New("kubeevent: the API server named no Event")
	}
	return made.Metadata.Name, nil
}

// raise sets a window's Event count and last time.
func (recorder *Recorder) raise(ctx context.Context, name string, count int, now time.Time) error {
	body, err := json.Marshal(map[string]any{"count": count, "lastTimestamp": now.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	_, err = recorder.call(ctx, http.MethodPatch, recorder.events+"/"+url.PathEscape(name),
		"application/merge-patch+json", body, http.StatusOK)
	return err
}

func (recorder *Recorder) call(ctx context.Context, method, target, contentType string, body []byte, want int,
) ([]byte, error) {
	token, err := os.ReadFile(recorder.options.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("kubeevent: reading the gateway's token: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", "application/json")
	response, err := recorder.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("kubeevent: calling the API server: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumAnswer))
	if err != nil {
		return nil, fmt.Errorf("kubeevent: reading the answer: %w", err)
	}
	if response.StatusCode == http.StatusNotFound && method == http.MethodPatch {
		return nil, errNotFound
	}
	if response.StatusCode != want {
		return nil, fmt.Errorf("kubeevent: the API server answered %d", response.StatusCode)
	}
	return payload, nil
}

func ownerText(owner string) string {
	if owner == "" {
		return "the Workspace"
	}
	return owner
}
