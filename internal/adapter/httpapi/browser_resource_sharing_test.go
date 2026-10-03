package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

func TestBrowserManagementReadsExactResourceCatalog(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	called := 0
	options.Management.resourceCatalog = managementResourceCatalogFixture{
		listResources: func(ctx context.Context, session accountsession.Session, scope network.Scope, state resource.State, limit int, cursor catalog.PageCursor) (catalog.ResourcePage, error) {
			called++
			if ctx.Err() != nil || !session.IsValid() || scope.WorkspaceID().String() != managementWorkspaceID() || scope.NetworkID().String() != managementNetworkID() || state != resource.StateActive || limit != 25 || cursor.IsValid() {
				t.Fatal("cookie catalog lost exact scope or request bounds")
			}
			return catalog.ResourcePage{Items: []catalog.Resource{}, Revision: 7}, nil
		},
	}
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	request := browserManagementReadRequest(t, resourceCollectionPath()+"?state=active&page_size=25")
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"7"` || called != 1 || fixture.auth < 1 || fixture.budgets != 2 {
		t.Fatalf("cookie catalog admission: status=%d calls=%d auth=%d budgets=%d", response.Code, called, fixture.auth, fixture.budgets)
	}
}

func TestBrowserResourceSharingAdmission(t *testing.T) {
	t.Parallel()
	collection := resourceCollectionPath()
	offer := sharingOfferCollectionPath()
	item := offer + "/01890f00-0000-7000-8000-000000000821"
	contract := collection[:len(collection)-len("resources")] + "trust-contracts/01890f00-0000-7000-8000-000000000822/actions/activate"
	for _, test := range []struct {
		name, method, path string
		want               bool
	}{
		{"resource list", http.MethodGet, collection + "?state=active&page_size=25", true},
		{"resource create", http.MethodPost, collection, true},
		{"resource get", http.MethodGet, collection + "/01890f00-0000-7000-8000-000000000501", true},
		{"offer list", http.MethodGet, offer + "?direction=incoming&state=offered&page_size=25", true},
		{"offer create", http.MethodPost, offer, true},
		{"offer get", http.MethodGet, item, true},
		{"offer accept", http.MethodPost, item + "/actions/accept", true},
		{"offer reject", http.MethodPost, item + "/actions/reject", true},
		{"offer revoke", http.MethodPost, item + "/actions/revoke", true},
		{"contract activate", http.MethodPost, contract, true},
		{"contract revoke", http.MethodPost, contract[:len(contract)-len("activate")] + "revoke", true},
		{"create query", http.MethodPost, collection + "?state=active", false},
		{"item query", http.MethodGet, item + "?direction=incoming", false},
		{"read action", http.MethodGet, item + "/actions/accept", false},
		{"write item", http.MethodPost, item, false},
		{"resource groups", http.MethodGet, collection[:len(collection)-len("resources")] + "resource-groups", false},
		{"resource rebind", http.MethodPost, collection + "/01890f00-0000-7000-8000-000000000501/actions/rebind", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			browser, fixture := newBrowserManagementFixture(t)
			request := browserManagementRequest(t, test.path, "{}")
			if test.method == http.MethodGet {
				request = browserManagementReadRequest(t, test.path)
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err := browser.Handle(response, request)
			if test.want && errors.Is(err, ErrInvalidBrowserManagement) {
				t.Fatalf("supported cookie operation rejected: %v", err)
			}
			if !test.want && (!errors.Is(err, ErrInvalidBrowserManagement) || fixture.auth != 0 || fixture.budgets != 0) {
				t.Fatal("unsupported request reached an effect")
			}
		})
	}
}

func TestBrowserShareCreationRequiresCurrentProof(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"valid", "missing proof", "expired proof", "body exhausts proof", "revoked Session", "Bearer header", "foreign origin"} {
		t.Run(mode, func(t *testing.T) {
			options, fixture := browserManagementTestOptions(t)
			share := managementSharingFixture(t, sharing.OfferStateOffered)
			called := 0
			options.Management.resourceSharing = &managementResourceSharingStub{create: func(_ context.Context, command sharing.CreateOffer) (sharing.MutationResult, error) {
				called++
				if !command.IsValid() || command.ProviderScope() != share.provider || command.ConsumerScope() != share.consumer {
					t.Fatal("share scope changed")
				}
				return share.createResult, nil
			}}
			browser, err := NewBrowserManagement(options)
			if err != nil {
				t.Fatal(err)
			}
			proof := preparedBrowserProof(t, browser)
			body := `{"consumer_workspace_id":"` + share.consumer.WorkspaceID().String() + `","consumer_network_id":"` + share.consumer.NetworkID().String() + `","resource_id":"` + share.binding.ResourceID().String() + `","maximum_traffic":[{"protocol":"tcp","destination_port_ranges":[{"first":443,"last":443}]}],"expires_at":"2026-09-30T00:00:00Z","reason":"exact Resource share"}`
			request := browserManagementRequest(t, sharingOfferCollectionPath(), body)
			request.Header.Del("If-Match")
			request.Header.Set("X-MeshTransit-CSRF", proof)
			switch mode {
			case "missing proof":
				request.Header.Del("X-MeshTransit-CSRF")
			case "expired proof":
				fixture.at = fixture.at.Add(2 * time.Minute)
			case "body exhausts proof":
				request.Body = io.NopCloser(&browserSharingProofDelay{Reader: strings.NewReader(body), advance: func() { fixture.at = fixture.at.Add(2 * time.Minute) }})
			case "revoked Session":
				fixture.sessionRevoked = true
			case "Bearer header":
				request.Header.Set("Authorization", "Bearer "+managementTokenFixture)
			case "foreign origin":
				request.Header.Set("Origin", "https://foreign.example.test")
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err = browser.Handle(response, request)
			if mode == "valid" {
				if err != nil || response.Code != http.StatusCreated || called != 1 || response.Header().Get("Location") != "" || response.Header().Get("WWW-Authenticate") != "" {
					t.Fatal("confirmed share lost the cookie contract", err)
				}
			} else if called != 0 {
				t.Fatal("invalid proof/Session reached sharing mutation")
			}
		})
	}
}

type browserSharingProofDelay struct {
	io.Reader
	advance func()
}

func (reader *browserSharingProofDelay) Read(target []byte) (int, error) {
	if reader.advance != nil {
		reader.advance()
		reader.advance = nil
	}
	return reader.Reader.Read(target)
}
