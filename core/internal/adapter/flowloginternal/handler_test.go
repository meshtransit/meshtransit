package flowloginternal

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// fakeReader answers what a test set, counting reads.
type fakeReader struct {
	mu            sync.Mutex
	networks      []connectionlog.ReceiverNetwork
	destination   connectionlog.ReceiverDestination
	revocations   []connectionlog.ReceiverRevocation
	fail          error
	afters        []network.ID
	limits        []int
	scopes        []network.Scope
	revocationsAt int
	// block, when set, holds a revocation read until closed.
	block chan struct{}
}

func (reader *fakeReader) Networks(_ context.Context, after network.ID, limit int,
) (connectionlog.ReceiverNetworks, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.afters, reader.limits = append(reader.afters, after), append(reader.limits, limit)
	if reader.fail != nil {
		return connectionlog.ReceiverNetworks{}, reader.fail
	}
	listed := reader.networks
	if len(listed) > limit {
		listed = listed[:limit]
	}
	return connectionlog.ReceiverNetworks{Networks: listed, GeneratedAt: time.Unix(1_900_000_000, 0)}, nil
}

func (reader *fakeReader) Destination(_ context.Context, scope network.Scope) (connectionlog.ReceiverDestination, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.scopes = append(reader.scopes, scope)
	if reader.fail != nil {
		return connectionlog.ReceiverDestination{}, reader.fail
	}
	if reader.destination.Reason == "" {
		return connectionlog.ReceiverDestination{}, ErrNotFound
	}
	return reader.destination, nil
}

func (reader *fakeReader) Revocations(context.Context) (connectionlog.ReceiverRevocations, error) {
	reader.mu.Lock()
	block := reader.block
	reader.revocationsAt++
	reader.mu.Unlock()
	if block != nil {
		<-block
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.fail != nil {
		return connectionlog.ReceiverRevocations{}, reader.fail
	}
	return connectionlog.ReceiverRevocations{Revocations: reader.revocations, GeneratedAt: time.Unix(1_900_000_000, 0)}, nil
}

func (reader *fakeReader) set(change func(*fakeReader)) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	change(reader)
}

func testID(index int) publicid.ID {
	return must(publicid.Parse(fmt.Sprintf("01890f00-0000-7000-8000-%012x", index)))
}

func (f fixture) receiver(t *testing.T) *http.Client {
	t.Helper()
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	return f.client(&good, nil)
}

func decode[T proto.Message](t *testing.T, body []byte, message T) T {
	t.Helper()
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, message); err != nil {
		t.Fatal(err)
	}
	return message
}

// Revocations are read once a second per replica, whatever the requests.
func TestRevocationsShareOneReadASecond(t *testing.T) {
	reader := &fakeReader{revocations: []connectionlog.ReceiverRevocation{{
		Network: network.ID(testID(1)), Device: node.ID(testID(2)), MachineKey: [32]byte{7},
	}}}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	var tag string
	for range 5 {
		response, body, err := get(t, client, f.base+revocationsPath, nil)
		if err != nil || response.status != http.StatusOK {
			t.Fatalf("GET revocations = %v, %v", response, err)
		}
		revoked := decode(t, body, &flowlogv1.FlowRevocations{})
		if len(revoked.GetRevocations()) != 1 || revoked.GetRevocations()[0].GetMachineKey()[0] != 7 ||
			revoked.GetGeneratedAtMs() != 1_900_000_000_000 {
			t.Fatalf("revocations = %v", revoked)
		}
		tag = response.header.Get("ETag")
	}
	if reader.revocationsAt != 1 {
		t.Fatalf("read %d times within a second", reader.revocationsAt)
	}
	f.clock.advance(revocationAge)
	if response, _, err := get(t, client, f.base+revocationsPath, http.Header{"If-None-Match": {tag}}); err != nil ||
		response.status != http.StatusNotModified || reader.revocationsAt != 2 {
		t.Fatalf("after a second: %v, %v, %d reads", response, err, reader.revocationsAt)
	}
	reader.set(func(r *fakeReader) { r.fail = errors.New("database down") })
	f.clock.advance(revocationAge)
	for range 3 {
		if response, _, err := get(t, client, f.base+revocationsPath, nil); err != nil ||
			response.status != http.StatusServiceUnavailable || response.header.Get("Retry-After") == "" {
			t.Fatalf("a failed read: %v, %v", response, err)
		}
	}
	// A failure answers for a second too.
	if reader.revocationsAt != 3 {
		t.Fatalf("an outage read %d times", reader.revocationsAt)
	}
	reader.set(func(r *fakeReader) { r.fail = ErrRevocationsCut })
	f.clock.advance(revocationAge)
	if response, _, err := get(t, client, f.base+revocationsPath, nil); err != nil ||
		response.status != http.StatusServiceUnavailable {
		t.Fatalf("a cut list: %v, %v", response, err)
	}
	if cut := metricTotal(t, f.metrics, "meshtransit_flowlog_internal_requests_total"); cut == 0 {
		t.Fatal("no request counted")
	}
}

// Requests during one slow read all wait on it.
func TestRevocationsShareTheReadInFlight(t *testing.T) {
	reader := &fakeReader{block: make(chan struct{})}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	var wait sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wait.Go(func() {
			response, _, err := get(t, client, f.base+revocationsPath, nil)
			if err != nil {
				statuses <- 0
				return
			}
			statuses <- response.status
		})
	}
	for {
		reader.mu.Lock()
		started := reader.revocationsAt
		reader.mu.Unlock()
		if started > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the other requests join the read
	close(reader.block)
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
	}
	if reader.revocationsAt != 1 {
		t.Fatalf("read %d times", reader.revocationsAt)
	}
}

// Networks page by ID; a full page names where the next starts; a large
// page goes gzipped.
func TestNetworksPage(t *testing.T) {
	reader := &fakeReader{}
	for index := range 3000 {
		reader.networks = append(reader.networks, connectionlog.ReceiverNetwork{
			Workspace: workspace.ID(testID(1)), Network: network.ID(testID(100 + index)), Enabled: index%2 == 0,
			SettingsVersion: 1, Credential: connectionlog.CredentialID(testID(9)), SealedVersion: 1,
			SealingKeyID: "meshflow-1",
		})
	}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	after := network.ID(testID(5)).String()
	response, body, err := get(t, client, f.base+networksPath+"?after="+after+"&limit=2000", nil)
	if err != nil || response.status != http.StatusOK {
		t.Fatalf("GET networks = %v, %v", response, err)
	}
	listed := decode(t, body, &flowlogv1.FlowNetworks{})
	last := network.ID(testID(100 + 1999)).Bytes()
	if len(listed.GetNetworks()) != 2000 || !bytes.Equal(listed.GetNextAfter(), last[:]) ||
		reader.afters[0] != network.ID(testID(5)) || reader.limits[0] != 2000 ||
		!listed.GetNetworks()[0].GetEnabled() || listed.GetNetworks()[1].GetEnabled() ||
		len(listed.GetNetworks()[0].GetDestinationEtag()) != 16 {
		t.Fatalf("page = %d networks, next %x", len(listed.GetNetworks()), listed.GetNextAfter())
	}
	// The client asked for gzip implicitly and got it undone; the tag of a
	// gzipped answer is weak.
	if response.header.Get("Content-Type") != contentType || !strings.HasPrefix(response.header.Get("ETag"), "W/") {
		t.Fatalf("content type %q, tag %q", response.header.Get("Content-Type"), response.header.Get("ETag"))
	}
	reader.set(func(r *fakeReader) { r.networks = r.networks[:3] })
	response, body, _ = get(t, client, f.base+networksPath, nil)
	if listed := decode(t, body, &flowlogv1.FlowNetworks{}); response.status != http.StatusOK ||
		len(listed.GetNetworks()) != 3 || listed.GetNextAfter() != nil || reader.limits[1] != defaultNetworkPage {
		t.Fatalf("a short page = %v", listed)
	}
	for _, query := range []string{"?limit=0", "?limit=5001", "?limit=x", "?after=nope", "?after=" + "01890F00-0000-7000-8000-000000000005"} {
		if response, _, err := get(t, client, f.base+networksPath+query, nil); err != nil ||
			response.status != http.StatusBadRequest {
			t.Errorf("%s: %v, %v", query, response, err)
		}
	}
}

// A destination is read for the exact scope; a deletion carries no
// credential; no destination and a malformed path are both 404.
func TestDestination(t *testing.T) {
	sealed := []byte("sealed credential")
	reader := &fakeReader{destination: connectionlog.ReceiverDestination{
		Reason: connectionlog.ReasonLogging, Forwarded: true, WindowSeconds: 120, Bucket: "logs", Region: "auto",
		Prefix: "mesh", SettingsVersion: 3, Credential: connectionlog.CredentialID(testID(9)), Provider: "cloudflare_r2",
		AccountID: "0123456789abcdef0123456789abcdef", Sealed: sealed, SealedVersion: 2, SealingKeyID: "meshflow-1",
		GeneratedAt: time.Unix(1_900_000_000, 0),
	}}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	workspaceID, networkID := workspace.ID(testID(1)).String(), network.ID(testID(2)).String()
	path := scopedPrefix + workspaceID + "/networks/" + networkID + "/destination"
	response, body, err := get(t, client, f.base+path, nil)
	if err != nil || response.status != http.StatusOK {
		t.Fatalf("GET destination = %v, %v", response, err)
	}
	destination := decode(t, body, &flowlogv1.FlowDestination{})
	credential := destination.GetCredential()
	if destination.GetReason() != flowlogv1.FlowDestination_LOGGING || destination.GetWindowS() != 120 ||
		credential.GetProvider() != flowlogv1.FlowDestination_CLOUDFLARE_R2 || !bytes.Equal(credential.GetSealed(), sealed) ||
		credential.GetSealedVersion() != 2 || len(destination.GetDestinationEtag()) != 16 ||
		reader.scopes[0].WorkspaceID().String() != workspaceID || reader.scopes[0].NetworkID().String() != networkID {
		t.Fatalf("destination = %v", destination)
	}
	reader.set(func(r *fakeReader) {
		r.destination = connectionlog.ReceiverDestination{
			Reason: connectionlog.ReasonNetworkDeleted, SettingsVersion: 3, GeneratedAt: time.Now(),
		}
	})
	if _, body, _ := get(t, client, f.base+path, nil); decode(t, body, &flowlogv1.FlowDestination{}).GetCredential() != nil {
		t.Fatal("a deleted Network carried a credential")
	}
	reader.set(func(r *fakeReader) { r.destination = connectionlog.ReceiverDestination{} })
	for _, target := range []string{
		path,
		scopedPrefix + workspaceID + "/networks/" + networkID + "/directory",
		scopedPrefix + "nope/networks/" + networkID + "/destination",
		scopedPrefix + workspaceID + "/networks/" + networkID + "/destination/extra",
	} {
		if response, _, err := get(t, client, f.base+target, nil); err != nil || response.status != http.StatusNotFound {
			t.Errorf("%s: %v, %v", target, response, err)
		}
	}
	reader.set(func(r *fakeReader) { r.fail = errors.New("database down") })
	if response, _, err := get(t, client, f.base+path, nil); err != nil || response.status != http.StatusServiceUnavailable {
		t.Fatalf("a failed read: %v, %v", response, err)
	}
}
