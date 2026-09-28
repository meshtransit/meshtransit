package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
)

func TestManagementHandlerPublishesPolicy(t *testing.T) {
	t.Parallel()

	session := managementSessionFixture(t)
	var captured policypublication.Command
	handler := managementHandlerFixture(t, managementHandlerFixtureOptions{
		session: session,
		publish: func(
			_ context.Context,
			command policypublication.Command,
		) (policypublication.Result, error) {
			captured = command
			return managementPolicyResultFixture(t, command), nil
		},
	})
	request := newManagementRequest(
		t,
		http.MethodPost,
		validPolicyPublishPath(),
		validPolicyPublishBody(),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if !captured.IsValid() || !captured.HasAccountSession() ||
		captured.AccountSession().ID() != session.ID() ||
		captured.ActorPrincipalID() != session.PrincipalID() ||
		captured.BasePolicyRevision() != 1 ||
		captured.Candidate().Snapshot().Scope().WorkspaceID().String() != managementWorkspaceID() ||
		captured.Candidate().Snapshot().Scope().NetworkID().String() != managementNetworkID() ||
		len(captured.Candidate().Snapshot().Rules()) != 4 {
		t.Fatalf("captured command = %+v, want exact Account-Session-bound policy", captured)
	}
	rules := captured.Candidate().Snapshot().Rules()
	if rules[2].Protocol().String() != "tcp" || len(rules[2].DestinationPortRanges()) != 2 ||
		rules[2].DestinationPortRanges()[0].First() != 80 ||
		rules[2].DestinationPortRanges()[0].Last() != 81 ||
		rules[2].DestinationPortRanges()[1].First() != 443 ||
		rules[3].Protocol().String() != "udp" || len(rules[3].DestinationPortRanges()) != 1 ||
		rules[3].DestinationPortRanges()[0].First() != 53 {
		t.Fatalf("captured transport rules = %+v, want canonical TCP and UDP ranges", rules[2:])
	}
	if response.Header().Get("ETag") != `"2"` ||
		response.Header().Get("X-Correlation-ID") != managementCorrelationID() {
		t.Fatalf("response headers = %+v", response.Header())
	}
	var body publishPolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body = %s", err, response.Body.String())
	}
	if body.Data.ReleaseID == "" || body.Data.PolicyRevision != 2 ||
		body.Data.NetworkRevision != 8 || len(body.Data.SemanticHash) != 64 ||
		body.Data.RuleCount != 4 || body.CorrelationID != managementCorrelationID() {
		t.Fatalf("response body = %+v", body)
	}
}

func TestManagementHandlerPolicyPublicationFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		publishErr error
		status     int
		code       string
		wantCall   bool
	}{
		{
			name:   "missing policy precondition",
			mutate: func(request *http.Request) { request.Header.Del("If-Match") },
			status: http.StatusPreconditionRequired, code: "precondition_required",
		},
		{
			name: "nil rule set", body: `{"reason":"deny all","rules":null}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "unknown protocol",
			body:   `{"reason":"bad","rules":[{"id":"01890f00-0000-7000-8000-000000000501","source_device_id":"01890f00-0000-7000-8000-000000000301","destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"any","destination_port_ranges":[]}]}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "tcp without ports",
			body:   `{"reason":"bad","rules":[{"id":"01890f00-0000-7000-8000-000000000501","source_device_id":"01890f00-0000-7000-8000-000000000301","destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"tcp","destination_port_ranges":[]}]}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "udp zero port",
			body:   `{"reason":"bad","rules":[{"id":"01890f00-0000-7000-8000-000000000501","source_device_id":"01890f00-0000-7000-8000-000000000301","destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"udp","destination_port_ranges":[{"first":0,"last":53}]}]}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "tcp port overflow",
			body:   `{"reason":"bad","rules":[{"id":"01890f00-0000-7000-8000-000000000501","source_device_id":"01890f00-0000-7000-8000-000000000301","destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"tcp","destination_port_ranges":[{"first":443,"last":65536}]}]}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name: "forbidden", publishErr: policypublication.ErrForbidden,
			status: http.StatusForbidden, code: "forbidden", wantCall: true,
		},
		{
			name: "stale revision", publishErr: policypublication.ErrConflict,
			status: http.StatusPreconditionFailed, code: "precondition_failed", wantCall: true,
		},
		{
			name: "publication unavailable", publishErr: policypublication.ErrRetryExhausted,
			status: http.StatusServiceUnavailable, code: "operation_unavailable", wantCall: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			handler := managementHandlerFixture(t, managementHandlerFixtureOptions{
				publish: func(
					_ context.Context,
					command policypublication.Command,
				) (policypublication.Result, error) {
					called = true
					if test.publishErr != nil {
						return policypublication.Result{}, errors.Join(
							policypublication.ErrPublicationFailed,
							test.publishErr,
							errors.New("private database detail"),
						)
					}
					return managementPolicyResultFixture(t, command), nil
				},
			})
			body := test.body
			if body == "" {
				body = validPolicyPublishBody()
			}
			request := newManagementRequest(t, http.MethodPost, validPolicyPublishPath(), body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
			var envelope managementErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
				envelope.Error.Code != test.code || called != test.wantCall {
				t.Fatalf("error/called = (%+v, %v)/%t, want code %q/called %t", envelope, err, called, test.code, test.wantCall)
			}
		})
	}
}

func validPolicyPublishPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/policy/actions/publish"
}

func validPolicyPublishBody() string {
	return `{"reason":"allow node health probes","rules":[` +
		`{"id":"01890f00-0000-7000-8000-000000000501",` +
		`"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
		`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
		`"protocol":"icmp","destination_port_ranges":[]},` +
		`{"id":"01890f00-0000-7000-8000-000000000502",` +
		`"source_device_id":"01890f00-0000-7000-8000-000000000302",` +
		`"destination_device_id":"01890f00-0000-7000-8000-000000000301",` +
		`"protocol":"icmp","destination_port_ranges":[]},` +
		`{"id":"01890f00-0000-7000-8000-000000000503",` +
		`"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
		`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
		`"protocol":"tcp","destination_port_ranges":[{"first":443,"last":443},{"first":80,"last":81}]},` +
		`{"id":"01890f00-0000-7000-8000-000000000504",` +
		`"source_device_id":"01890f00-0000-7000-8000-000000000302",` +
		`"destination_device_id":"01890f00-0000-7000-8000-000000000301",` +
		`"protocol":"udp","destination_port_ranges":[{"first":53,"last":53}]}]}`
}
