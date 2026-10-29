// Package kubetoken mints the short-lived ServiceAccount tokens a
// Kubernetes gateway forwards a mesh Device's requests with: one per
// Device, owner and group, for the group's mt-<group> account, bound to the
// gateway's pod (K1-I2; K1b design §6, Q61). It talks to the API server over
// plain REST with the pod's own token, without client-go.
//
// The caller decides that the Device and its owner may use the group; the
// minter only mints for it.
package kubetoken

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/time/rate"
)

var (
	// ErrLimited reports a mint that would wait past QueueWait for the rate.
	ErrLimited = errors.New("kubetoken: mint rate limit")
	// ErrClosed reports a minter that no longer mints.
	ErrClosed = errors.New("kubetoken: closed")
	// errKey reports a key the minter refuses: an empty Device or owner, or
	// a group that is not a DNS label.
	errKey = errors.New("kubetoken: a Device, an owner and a DNS label group are required")
)

const (
	// maxResponse bounds what is read of an answer.
	maxResponse = 64 << 10
	// requestTimeout bounds one TokenRequest.
	requestTimeout = 10 * time.Second
	// usableMargin: a token is handed out until this long before it
	// expires, while its refresh runs in the background (review b3 H1).
	usableMargin = 30 * time.Second
	// minimumLife is the shortest life an answer may give a token: past its
	// refresh window and usable margin, or every use would mint again.
	minimumLife = 5 * time.Minute
	// failureBackoff bounds how soon a key's failed mint is tried again
	// when the API server named no wait (review b3 L6).
	failureBackoff = time.Second
)

// Options bound a minter (K1b design §6, Q61).
type Options struct {
	// Server is the API server's https URL; CAFile its CA; TokenFile the
	// gateway's own token, read for every request; Namespace the gateway's.
	Server, CAFile, TokenFile, Namespace string
	// BoundSecret and BoundSecretUID bind each token to the replica's own
	// state Secret: deleting it, as a new join does, revokes the tokens,
	// and the token's claims name the replica. A Pod cannot be the bound
	// object: the API server binds a token only to a pod running as the
	// token's own ServiceAccount, never the gateway's (kind demo b5b).
	BoundSecret, BoundSecretUID string
	// ExpirationSeconds is each token's life.
	ExpirationSeconds int64
	// RefreshFrom and RefreshTo: a token is minted again this long before
	// it expires, at random between the two.
	RefreshFrom, RefreshTo time.Duration
	// Capacity bounds the tokens kept, one per Device, owner and group:
	// the map's peer limit times the groups a Device uses (review b3 M4).
	Capacity int
	// Rate and Burst bound mints; one that would wait past QueueWait fails.
	Rate, Burst float64
	QueueWait   time.Duration
	// Now is the clock tokens expire by; nil: time.Now.
	Now func() time.Time
}

// DefaultOptions are the design's: 600 s tokens refreshed 120–240 s before
// they expire, 20,000 kept (10,000 Devices of two groups), 50 mints a
// second, burst 200, a 10 s queue.
func DefaultOptions() Options {
	return Options{ExpirationSeconds: 600, RefreshFrom: 120 * time.Second, RefreshTo: 240 * time.Second,
		Capacity: 20000, Rate: 50, Burst: 200, QueueWait: 10 * time.Second}
}

func (options Options) valid() bool {
	server, err := url.Parse(options.Server)
	return err == nil && server.Scheme == "https" && server.Host != "" && server.User == nil &&
		server.RawQuery == "" && server.Fragment == "" && options.CAFile != "" && options.TokenFile != "" &&
		dnsLabel(options.Namespace) && options.BoundSecret != "" && options.BoundSecretUID != "" &&
		options.ExpirationSeconds >= 600 && options.RefreshFrom > usableMargin &&
		options.RefreshTo >= options.RefreshFrom &&
		options.RefreshTo < time.Duration(options.ExpirationSeconds)*time.Second && options.Capacity >= 1 &&
		options.Rate > 0 && options.Burst >= 1 && options.QueueWait > 0
}

// Token is a minted token. Its value sits behind a pointer, so no
// formatting of a Token, or of a struct holding one, prints it (review b3
// M1).
type Token struct {
	held *secret
}

type secret struct {
	value   string
	id      []byte
	expires time.Time // by the minter's clock
}

// Value is the bearer token.
func (token Token) Value() string {
	if token.held == nil {
		return ""
	}
	return token.held.value
}

// ID is the token's jti, at most 16 bytes; nil when it has none.
func (token Token) ID() []byte {
	if token.held == nil {
		return nil
	}
	return bytes.Clone(token.held.id)
}

// Expires is when the token stops working, by the minter's clock.
func (token Token) Expires() time.Time {
	if token.held == nil {
		return time.Time{}
	}
	return token.held.expires
}

// String redacts the token.
func (token Token) String() string {
	return "kubetoken.Token(id=" + hex.EncodeToString(token.ID()) + ", [REDACTED])"
}

// GoString redacts detailed formatting.
func (token Token) GoString() string { return token.String() }

// Format redacts every verb.
func (token Token) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, token.String()) }

// LogValue redacts structured formatting.
func (token Token) LogValue() slog.Value { return slog.StringValue(token.String()) }

// MintError is the API server's refusal of a mint: its status, its cleaned
// reason and the wait it asked for. It never holds the answer's body.
type MintError struct {
	Status     int
	Reason     string
	RetryAfter time.Duration
}

func (err *MintError) Error() string {
	return fmt.Sprintf("kubetoken: the API server answered %d: %s", err.Status, err.Reason)
}

// key names the token a request may use.
type key struct {
	device, owner, group string
}

type entry struct {
	key       key
	token     Token
	refreshAt time.Time
}

type flight struct {
	done  chan struct{}
	token Token
	err   error
}

// failure is a key's last failed mint, tried again after until.
type failure struct {
	err   error
	until time.Time
}

// Minter mints and keeps tokens.
type Minter struct {
	options   Options
	client    *http.Client
	closeIdle func()
	base      string
	limiter   *rate.Limiter

	mu       sync.Mutex
	entries  map[key]*list.Element // of *entry, most recent first
	recent   *list.List
	flights  map[key]*flight
	failures map[key]failure
	// heldUntil: the API server asked the gateway to wait (429); no mint
	// leaves before (review b3 L4).
	heldUntil time.Time
	closed    bool
	mints     sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// New makes a minter for an API server.
func New(options Options) (*Minter, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if !options.valid() {
		return nil, errors.New("kubetoken: invalid options")
	}
	pem, err := os.ReadFile(options.CAFile)
	if err != nil {
		return nil, fmt.Errorf("kubetoken: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("kubetoken: the cluster CA file holds no certificate")
	}
	// No proxy from the environment, no redirect: the gateway's token goes
	// to the API server only.
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
		HTTP2:             &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Minter{options: options, closeIdle: transport.CloseIdleConnections,
		client: &http.Client{Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base: strings.TrimSuffix(options.Server, "/") + "/api/v1/namespaces/" + url.PathEscape(options.Namespace) +
			"/serviceaccounts/",
		limiter: rate.NewLimiter(rate.Limit(options.Rate), int(options.Burst)),
		entries: map[key]*list.Element{}, recent: list.New(), flights: map[key]*flight{},
		failures: map[key]failure{}, ctx: ctx, cancel: cancel}, nil
}

// Close stops minting: For answers ErrClosed, mints under way end, and
// Close returns once they did.
func (minter *Minter) Close() {
	minter.mu.Lock()
	minter.closed = true
	minter.mu.Unlock()
	minter.cancel()
	minter.mints.Wait()
	minter.closeIdle()
}

// For returns a token of group's account for device and owner. The kept
// token is handed out until shortly before it expires; from its refresh
// time a new one is minted in the background (review b3 H1). Without a
// usable token the caller waits for the mint, which callers of one key
// share and which runs apart from any one caller.
func (minter *Minter) For(ctx context.Context, device, owner, group string) (Token, error) {
	if device == "" || owner == "" || !dnsLabel(group) {
		return Token{}, errKey
	}
	id := key{device: device, owner: owner, group: group}
	minter.mu.Lock()
	if minter.closed {
		minter.mu.Unlock()
		return Token{}, ErrClosed
	}
	now := minter.options.Now()
	if element, found := minter.entries[id]; found {
		held := element.Value.(*entry) //nolint:forcetypeassert // only *entry is stored
		if now.Before(held.token.Expires().Add(-usableMargin)) {
			minter.recent.MoveToFront(element)
			if !now.Before(held.refreshAt) {
				minter.startLocked(id, now)
			}
			minter.mu.Unlock()
			return held.token, nil
		}
	}
	shared := minter.startLocked(id, now)
	if shared == nil {
		err := minter.failures[id].err
		minter.mu.Unlock()
		return Token{}, err
	}
	minter.mu.Unlock()
	select {
	case <-shared.done:
		return shared.token, shared.err
	case <-ctx.Done():
		return Token{}, ctx.Err()
	}
}

// startLocked starts, or joins, the key's mint; nil while the key backs off
// after a failure.
func (minter *Minter) startLocked(id key, now time.Time) *flight {
	if shared, found := minter.flights[id]; found {
		return shared
	}
	if failed, found := minter.failures[id]; found && now.Before(failed.until) {
		return nil
	}
	shared := &flight{done: make(chan struct{})}
	minter.flights[id] = shared
	minter.mints.Add(1)
	go minter.mint(id, shared)
	return shared
}

// Forget drops the kept token of a key if it is still token: the API server
// refused it (401). A token minted since stays.
func (minter *Minter) Forget(device, owner, group string, token Token) {
	minter.mu.Lock()
	defer minter.mu.Unlock()
	id := key{device: device, owner: owner, group: group}
	if element, found := minter.entries[id]; found &&
		element.Value.(*entry).token.held == token.held { //nolint:forcetypeassert // only *entry is stored
		minter.recent.Remove(element)
		delete(minter.entries, id)
	}
}

// mint mints one token for a flight, keeps it or the failure, and ends the
// flight. A failed refresh keeps the token still usable.
func (minter *Minter) mint(id key, shared *flight) {
	defer minter.mints.Done()
	token, err := minter.request(id)
	minter.mu.Lock()
	defer minter.mu.Unlock()
	delete(minter.flights, id)
	if err != nil && minter.ctx.Err() != nil {
		err = ErrClosed
	}
	shared.token, shared.err = token, err
	close(shared.done)
	now := minter.options.Now()
	if err != nil {
		wait := failureBackoff
		var refused *MintError
		if errors.As(err, &refused) && refused.RetryAfter > 0 {
			wait = min(refused.RetryAfter, time.Minute)
		}
		if errors.As(err, &refused) && refused.Status == http.StatusTooManyRequests {
			// The API server's flow control holds the whole gateway.
			if until := time.Now().Add(wait); until.After(minter.heldUntil) {
				minter.heldUntil = until
			}
		}
		if len(minter.failures) >= minter.options.Capacity {
			for other, failed := range minter.failures {
				if !now.Before(failed.until) {
					delete(minter.failures, other)
				}
			}
		}
		if len(minter.failures) < minter.options.Capacity {
			minter.failures[id] = failure{err: err, until: now.Add(wait)}
		}
		return
	}
	delete(minter.failures, id)
	refresh := minter.options.RefreshFrom +
		time.Duration(rand.Int64N(int64(minter.options.RefreshTo-minter.options.RefreshFrom)+1)) //nolint:gosec // jitter
	held := &entry{key: id, token: token, refreshAt: token.Expires().Add(-refresh)}
	if element, found := minter.entries[id]; found {
		element.Value = held
		minter.recent.MoveToFront(element)
		return
	}
	minter.entries[id] = minter.recent.PushFront(held)
	for minter.recent.Len() > minter.options.Capacity {
		oldest := minter.recent.Back()
		minter.recent.Remove(oldest)
		delete(minter.entries, oldest.Value.(*entry).key) //nolint:forcetypeassert // only *entry is stored
	}
}

// request waits its turn, then asks the API server for a token. The token's
// life is measured from before the request on the minter's clock, never
// read off the API server's (review b3 M2).
func (minter *Minter) request(id key) (Token, error) {
	if err := minter.waitTurn(); err != nil {
		return Token{}, err
	}
	gateway, err := os.ReadFile(minter.options.TokenFile)
	if err != nil {
		return Token{}, fmt.Errorf("kubetoken: reading the gateway's token: %w", err)
	}
	body, err := json.Marshal(tokenRequest{APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest",
		Spec: tokenRequestSpec{ExpirationSeconds: minter.options.ExpirationSeconds,
			BoundObjectRef: boundObject{Kind: "Secret", APIVersion: "v1", Name: minter.options.BoundSecret,
				UID: minter.options.BoundSecretUID}}})
	if err != nil {
		return Token{}, err
	}
	ctx, cancel := context.WithTimeout(minter.ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		minter.base+url.PathEscape("mt-"+id.group)+"/token", bytes.NewReader(body))
	if err != nil {
		return Token{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(gateway)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	started := minter.options.Now()
	response, err := minter.client.Do(request)
	if err != nil {
		minter.closeIdle() // the connection may be dead
		return Token{}, fmt.Errorf("kubetoken: minting for mt-%s: %w", id.group, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		minter.closeIdle()
		return Token{}, fmt.Errorf("kubetoken: reading the answer: %w", err)
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return Token{}, &MintError{Status: response.StatusCode, Reason: statusReason(payload),
			RetryAfter: retryAfter(response.Header.Get("Retry-After"))}
	}
	var answer struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(payload, &answer); err != nil || !tokenText(answer.Status.Token) ||
		answer.Status.ExpirationTimestamp.IsZero() {
		return Token{}, fmt.Errorf("kubetoken: minting for mt-%s: an answer without a token and its expiry",
			id.group)
	}
	life := tokenLife(answer.Status.Token, answer.Status.ExpirationTimestamp, response.Header.Get("Date"),
		time.Duration(minter.options.ExpirationSeconds)*time.Second)
	if life < minimumLife {
		return Token{}, fmt.Errorf("kubetoken: minting for mt-%s: a token of %v", id.group, life)
	}
	return Token{held: &secret{value: answer.Status.Token, id: tokenID(answer.Status.Token),
		expires: started.Add(life)}}, nil
}

// tokenLife is how long a token lives: what was asked, cut to what its
// claims say (exp - iat) and to its expiry less the answer's Date, all on
// the API server's own clock.
func tokenLife(token string, expires time.Time, date string, asked time.Duration) time.Duration {
	life := asked
	if claims, ok := tokenClaims(token); ok && claims.Expires > 0 && claims.IssuedAt > 0 {
		life = min(life, time.Duration(claims.Expires-claims.IssuedAt)*time.Second)
	}
	if sent, err := http.ParseTime(date); err == nil && !expires.IsZero() {
		life = min(life, expires.Sub(sent))
	}
	return life
}

// waitTurn reserves a mint: one that would wait past QueueWait fails at
// once and gives its turn back (review b3 M3).
func (minter *Minter) waitTurn() error {
	minter.mu.Lock()
	held := time.Until(minter.heldUntil)
	minter.mu.Unlock()
	if held > minter.options.QueueWait {
		return ErrLimited
	}
	if held > 0 && !minter.sleep(held) {
		return ErrClosed
	}
	reservation := minter.limiter.Reserve()
	delay := reservation.Delay()
	if !reservation.OK() || delay > minter.options.QueueWait {
		reservation.Cancel()
		return ErrLimited
	}
	if delay == 0 {
		return nil
	}
	if !minter.sleep(delay) {
		reservation.Cancel()
		return ErrClosed
	}
	return nil
}

// sleep waits for wait; false when the minter closed first.
func (minter *Minter) sleep(wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-minter.ctx.Done():
		return false
	}
}

// tokenText reports a token of the characters a JWT holds: base64url and
// dots, so a bad answer fails here, not as a header later.
func tokenText(token string) bool {
	if token == "" || len(token) > maxResponse {
		return false
	}
	for index := range len(token) {
		character := token[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

type tokenRequest struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Spec       tokenRequestSpec `json:"spec"`
}

type tokenRequestSpec struct {
	// Audiences is left out: the API server's own.
	Audiences         []string    `json:"audiences,omitempty"`
	ExpirationSeconds int64       `json:"expirationSeconds"`
	BoundObjectRef    boundObject `json:"boundObjectRef"`
}

type boundObject struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type claims struct {
	JTI      string `json:"jti"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

// tokenClaims reads a token's claims; they are not verified: the API
// server minted the token.
func tokenClaims(token string) (claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, false
	}
	var read claims
	if json.Unmarshal(payload, &read) != nil {
		return claims{}, false
	}
	return read, true
}

// tokenID is a token's jti, which the API server's audit records: a UUID's
// 16 bytes, else the first 16 bytes of its SHA-256; nil without one.
func tokenID(token string) []byte {
	read, ok := tokenClaims(token)
	if !ok || read.JTI == "" {
		return nil
	}
	if raw, err := hex.DecodeString(strings.ReplaceAll(read.JTI, "-", "")); err == nil && len(raw) == 16 &&
		len(read.JTI) == 36 {
		return raw
	}
	sum := sha256.Sum256([]byte(read.JTI))
	return sum[:16]
}

// statusReason is the reason of a Kubernetes Status answer, cleaned and
// bounded; never the body itself.
func statusReason(payload []byte) string {
	var status struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(payload, &status) != nil {
		return "unknown"
	}
	cleaned := strings.Map(func(character rune) rune {
		if character > unicode.MaxASCII || !unicode.IsLetter(character) {
			return -1
		}
		return character
	}, status.Reason)
	if cleaned == "" {
		return "unknown"
	}
	return cleaned[:min(len(cleaned), 64)]
}

// retryAfter is a Retry-After in seconds; 0 when absent or not one.
func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	return min(time.Duration(seconds)*time.Second, time.Hour)
}

// dnsLabel reports an RFC 1123 label.
func dnsLabel(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
