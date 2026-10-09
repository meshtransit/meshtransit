//go:build dexbroker

package dexbroker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"sync"
	"time"

	"github.com/AppsFlyer/go-sundheit"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage"
	"github.com/go-jose/go-jose/v4"
)

var (
	// ErrInvalidComponent indicates invalid immutable component input.
	ErrInvalidComponent = errors.New("invalid dex broker component")
	// ErrComponentStart indicates that the pinned component could not start.
	ErrComponentStart = errors.New("dex broker component start failed")
)

const (
	authorizationCodeGrant = "authorization_code"
	codeResponseType       = "code"
)

// componentOptions is product-owned input. Keeping it independent from Dex
// types confines version changes to this file.
type componentOptions struct {
	issuer                     string
	configuration              componentConfiguration
	idTokensValidFor           time.Duration
	authRequestsValidFor       time.Duration
	signingKeysRotateAfter     time.Duration
	garbageCollectionFrequency time.Duration
	logger                     *slog.Logger
	now                        func() time.Time
}

// componentResources contains version-specific resources assembled by this
// adapter. Storage is borrowed: the composition owner closes it only after the
// runtime and every storage observer have joined.
type componentResources struct {
	storage storage.Storage
}

// dexComponent adapts the pinned server to the product-owned runtime contract.
// Its done channel closes only after all server workers join.
type dexComponent struct {
	server              *server.Server
	signer              signer.Signer
	outboundHTTPClients *outboundHTTPClients
	cancel              context.CancelFunc
	doneCh              chan struct{}
	stopOnce            sync.Once
	mu                  sync.Mutex
	result              error
}

// newDexRuntime constructs the exact pinned server component. It deliberately
// does not create or own a network listener.
func newDexRuntime(ctx context.Context, options componentOptions, resources componentResources) (*Runtime, error) {
	component, err := newDexComponent(ctx, options, resources)
	if err != nil {
		return nil, err
	}
	if err := component.checkSigner(ctx); err != nil {
		component.stop()
		<-component.done()
		return nil, errors.Join(ErrComponentStart, ErrSignerCheck)
	}

	runtime, err := newRuntimeWithCancellation(component, ctx.Done())
	if err == nil {
		return runtime, nil
	}

	component.stop()
	<-component.done()
	return nil, errors.Join(ErrComponentStart, component.err())
}

func newDexComponent(ctx context.Context, options componentOptions, resources componentResources) (*dexComponent, error) {
	if isNilStorage(resources.storage) {
		return nil, ErrInvalidComponent
	}

	if ctx == nil || ctx.Err() != nil || !validComponentOptions(options) {
		return nil, ErrInvalidComponent
	}

	componentCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	now := options.now
	if now == nil {
		now = time.Now
	}
	utcNow := func() time.Time { return now().UTC() }
	serverStorage, err := withImmutableConfiguration(
		resources.storage,
		options.issuer,
		options.configuration,
	)
	if err != nil {
		cancel()
		return nil, ErrComponentStart
	}
	outboundHTTPClients, err := newOIDCOutboundHTTPClients(options.configuration)
	if err != nil {
		cancel()
		return nil, ErrComponentStart
	}

	localSigner, err := (&signer.LocalConfig{
		KeysRotationPeriod: options.signingKeysRotateAfter.String(),
	}).Open(componentCtx, serverStorage, options.idTokensValidFor, utcNow, options.logger)
	if err != nil {
		outboundHTTPClients.close()
		cancel()
		return nil, ErrComponentStart
	}

	dexServer, err := server.NewServer(componentCtx, server.Config{
		Issuer:                 options.issuer,
		Storage:                serverStorage,
		ConnectorHTTPClients:   outboundHTTPClients.clients,
		AllowedGrantTypes:      []string{authorizationCodeGrant},
		SupportedResponseTypes: []string{codeResponseType},
		Headers: http.Header{
			"Cache-Control":          []string{"no-store"},
			"Referrer-Policy":        []string{"no-referrer"},
			"X-Content-Type-Options": []string{"nosniff"},
		},
		SkipApprovalScreen:   true,
		IDTokensValidFor:     options.idTokensValidFor,
		AuthRequestsValidFor: options.authRequestsValidFor,
		GCFrequency:          options.garbageCollectionFrequency,
		Now:                  utcNow,
		Logger:               options.logger,
		Signer:               localSigner,
		HealthChecker:        gosundheit.New(),
	})
	if err != nil {
		outboundHTTPClients.close()
		cancel()
		return nil, ErrComponentStart
	}
	serverDone := dexServer.Done()
	if serverDone == nil {
		outboundHTTPClients.close()
		cancel()
		return nil, ErrComponentStart
	}

	component := &dexComponent{
		server: dexServer, signer: localSigner, outboundHTTPClients: outboundHTTPClients,
		cancel: cancel, doneCh: make(chan struct{}),
	}
	go component.ownLifecycle(serverDone)
	return component, nil
}

func validComponentOptions(options componentOptions) bool {
	if options.logger == nil || !validIssuer(options.issuer) {
		return false
	}
	return options.idTokensValidFor > 0 &&
		options.authRequestsValidFor > 0 &&
		options.signingKeysRotateAfter > 0 &&
		options.garbageCollectionFrequency > 0
}

func validIssuer(rawIssuer string) bool {
	issuer, err := url.Parse(rawIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return false
	}
	if issuer.Opaque != "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.RawPath != "" {
		return false
	}
	if issuer.Hostname() == "" || issuer.Path == "/" {
		return false
	}
	if issuer.Path == "" {
		return true
	}
	return path.Clean(issuer.Path) == issuer.Path && issuer.Path[len(issuer.Path)-1] != '/'
}

func isNilStorage(serverStorage storage.Storage) bool {
	if serverStorage == nil {
		return true
	}
	value := reflect.ValueOf(serverStorage)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (component *dexComponent) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	component.server.ServeHTTP(response, request)
}

const signerProbePayload = "meshtransit-signer-readiness-v1"

func (component *dexComponent) checkSigner(ctx context.Context) error {
	if component == nil || ctx == nil || ctx.Err() != nil || component.signer == nil {
		return ErrSignerCheck
	}
	algorithm, err := component.signer.Algorithm(ctx)
	if err != nil || algorithm != jose.RS256 {
		return ErrSignerCheck
	}
	keys, err := component.signer.ValidationKeys(ctx)
	if err != nil || len(keys) == 0 {
		return ErrSignerCheck
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == nil || key.KeyID == "" || key.Use != "sig" ||
			key.Algorithm != string(algorithm) || !key.IsPublic() {
			return ErrSignerCheck
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return ErrSignerCheck
		}
		seen[key.KeyID] = struct{}{}
	}
	signed, err := component.signer.Sign(ctx, []byte(signerProbePayload))
	if err != nil || signed == "" {
		return ErrSignerCheck
	}
	message, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		return ErrSignerCheck
	}
	for _, key := range keys {
		payload, verifyErr := message.Verify(key.Key)
		if verifyErr == nil && bytes.Equal(payload, []byte(signerProbePayload)) {
			return nil
		}
	}
	return ErrSignerCheck
}

func (component *dexComponent) stop() {
	component.stopOnce.Do(component.cancel)
}

func (component *dexComponent) done() <-chan struct{} {
	return component.doneCh
}

func (component *dexComponent) err() error {
	component.mu.Lock()
	defer component.mu.Unlock()
	return component.result
}

func (component *dexComponent) ownLifecycle(serverDone <-chan struct{}) {
	<-serverDone
	component.outboundHTTPClients.close()
	component.mu.Lock()
	close(component.doneCh)
	component.mu.Unlock()
}
