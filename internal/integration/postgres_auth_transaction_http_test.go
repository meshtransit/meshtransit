//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	adapteroidc "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

var _ httpapi.LoginRouteAdmission = (*postgresadapter.AuthTransactionStore)(nil)

func assertPostgreSQLBrowserLoginHTTP(ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthTransactionStore) {
	t.Helper()
	redis := openIntegrationRedisClient(ctx, t)
	for _, candidate := range []struct {
		name          string
		suffix        string
		generation    int64
		prepareStatus int
	}{
		{name: "durable http admission and creation", suffix: "961", generation: 1, prepareStatus: 200},
		{name: "durable http stale route", suffix: "962", generation: 2, prepareStatus: 503},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
				providerGeneration: candidate.generation, recoveryEpoch: 1,
				workspacePublicID: "01890f00-0000-7000-8000-000000000101",
			}, [4]string{
				"01890f00-0000-7000-8000-000000000" + candidate.suffix,
				"01890f01-0000-7000-8000-000000000" + candidate.suffix,
				"01890f02-0000-7000-8000-000000000" + candidate.suffix,
				"01890f03-0000-7000-8000-000000000" + candidate.suffix,
			})
			transactions := &integrationAuthStartTransactions{store: store}
			dependencies := integrationAuthStartDependencies(t, template, store, transactions)
			service, err := oidcauth.NewStartService(oidcauth.StartOptions{
				RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute,
				RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second,
			}, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(nil)
			defer server.Close()
			origin := "https://" + server.Listener.Addr().String()
			guard, err := adapteroidc.NewLoginInitiationGuard(adapteroidc.LoginInitiationOptions{
				Origin: origin, Route: template.Route(), KeyID: "integration-http-init-v1",
				KeyMaterial: bytes.Repeat([]byte{0x73}, 32), Lifetime: 2 * time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			rateID, err := ratelimit.NewDigestKeyID("integration-http-source-v1")
			if err != nil {
				t.Fatal(err)
			}
			digester, err := ratelimit.NewDigester(rateID, bytes.Repeat([]byte{0x72}, 32))
			if err != nil {
				t.Fatal(err)
			}
			policy, err := ratelimit.NewPolicy(100, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := httpapi.NewLoginStartHandler(httpapi.LoginStartHandlerOptions{
				Initiation: guard, Admission: store, Starter: service,
				RateLimitSubjects: digester, RateLimiter: redis, SourceRateLimit: policy,
				Clock: oidcauth.SystemStartClock{}, Observer: httpapi.NewLoginHTTPTelemetry(),
				RequestTimeout: 10 * time.Second, MaxConcurrentRequests: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.StartTLS()
			client := server.Client() // The local test certificate is explicitly trusted, never skipped.
			client.Timeout = 15 * time.Second
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			prepared, prepareBody := postIntegrationBrowserLogin(ctx, t, client, server.URL,
				httpapi.LoginPreparePath, "", nil)
			if prepared.statusCode != candidate.prepareStatus || prepared.header.Get("Cache-Control") != "no-store" {
				t.Fatalf("prepare status = %d, want %d with no-store", prepared.statusCode, candidate.prepareStatus)
			}
			if after := authAdmissionAuthorityCounts(ctx, t, admin); after != before {
				t.Fatal("HTTP prepare or rejected admission mutated durable authority")
			}
			if candidate.prepareStatus != 200 {
				if len(prepared.cookies) != 0 || transactions.begins != 0 || bytes.Contains(prepareBody, []byte("csrf_token")) {
					t.Fatal("stale admission released browser state or entered creation")
				}
				return
			}
			var preparation struct {
				CSRFToken string `json:"csrf_token"`
			}
			if err := json.Unmarshal(prepareBody, &preparation); err != nil || preparation.CSRFToken == "" {
				t.Fatal("prepare did not return a bounded proof")
			}
			cookies := prepared.cookies
			if len(cookies) != 1 || cookies[0].Name != adapteroidc.LoginInitiationCookieName ||
				!cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatal("prepare did not issue an independent secure initiation cookie")
			}
			started, startBody := postIntegrationBrowserLogin(ctx, t, client, server.URL,
				httpapi.LoginStartPath, preparation.CSRFToken, cookies[0])
			var result struct {
				AuthorizationURL string `json:"authorization_url"`
			}
			if started.statusCode != 200 || json.Unmarshal(startBody, &result) != nil || result.AuthorizationURL == "" {
				t.Fatalf("start status = %d, want confirmed authorization response", started.statusCode)
			}
			if len(started.cookies) != 2 || transactions.begins != 1 || transactions.creates != 1 || transactions.commits != 1 {
				t.Fatal("HTTP start did not rotate browser state after exactly one creation")
			}
			var durable, audit, outbox int
			if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.auth_transaction WHERE public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event WHERE target_public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event WHERE aggregate_public_id = $1::UUID)
`, template.TransactionID().String()).Scan(&durable, &audit, &outbox); err != nil {
				t.Fatal(err)
			}
			if durable != 1 || audit != 1 || outbox != 1 {
				t.Fatal("HTTP start released without atomic PostgreSQL transaction/audit/outbox")
			}
		})
	}
}

type integrationBrowserLoginResponse struct {
	statusCode int
	header     http.Header
	cookies    []*http.Cookie
}

func postIntegrationBrowserLogin(
	ctx context.Context,
	t *testing.T,
	client *http.Client,
	origin string,
	path string,
	proof string,
	cookie *http.Cookie,
) (integrationBrowserLoginResponse, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("X-MeshTransit-Login", "v1")
	request.Header.Set("Content-Type", "application/json")
	if proof != "" {
		request.Header.Set(adapteroidc.LoginCSRFHeader, proof)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > 4096 {
		t.Fatal("failed bounded browser response read/close")
	}
	// Body ownership ends here. Callers receive only detached response evidence,
	// never a live response body that they must close again.
	return integrationBrowserLoginResponse{
		statusCode: response.StatusCode, header: response.Header.Clone(), cookies: response.Cookies(),
	}, body
}
