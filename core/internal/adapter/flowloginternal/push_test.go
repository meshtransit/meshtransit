package flowloginternal

import (
	"bytes"
	"net/http"
	"slices"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/flowlog"
)

// A push destination reaches the receiver with what it binds the secret to,
// its CA PEM included, and the settings' fields of its type (schema 273).
func TestPushDestination(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	reader := &fakeReader{destination: connectionlog.ReceiverDestination{
		Reason: connectionlog.ReasonLogging, WindowSeconds: 60, SettingsVersion: 4,
		Credential: connectionlog.CredentialID(testID(9)), Provider: flowlog.ProviderElasticsearch,
		Sealed: []byte("sealed"), SealedVersion: 2, SealingKeyID: "meshflow-1",
		Push: connectionlog.Destination{
			URL: "https://es.example.com:9243", Flavor: flowlog.FlavorOpenSearch, CAPEM: ca,
		},
		Target: "meshtransit-connections", TargetKind: connectionlog.TargetKindIndex, GeneratedAt: time.Now(),
	}}
	f := startServerWith(t, reader)
	path := scopedPrefix + workspace.ID(testID(1)).String() + "/networks/" + network.ID(testID(2)).String() + "/destination"
	response, body, err := get(t, f.receiver(t), f.base+path, nil)
	if err != nil || response.status != http.StatusOK {
		t.Fatalf("GET destination = %v, %v", response, err)
	}
	destination := decode(t, body, &flowlogv1.FlowDestination{})
	push := destination.GetCredential().GetPush()
	if destination.GetCredential().GetProvider() != flowlogv1.FlowDestination_ELASTICSEARCH ||
		push.GetUrl() != "https://es.example.com:9243" || push.GetFlavor() != flowlog.FlavorOpenSearch ||
		!bytes.Equal(push.GetCaPem(), ca) || destination.GetTarget() != "meshtransit-connections" ||
		destination.GetTargetKind() != connectionlog.TargetKindIndex || destination.GetBucket() != "" {
		t.Fatalf("destination = %v", destination)
	}
}

// What a receiver writes to: none named is S3 and R2, a provider Core
// does not know is left out, each once in Core's order.
func TestDestinationTypes(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		named []flowlogv1.FlowDestination_Provider
		want  []string
	}{
		"none": {nil, []string{flowlog.ProviderS3, flowlog.ProviderR2}},
		"push and unknown, twice": {
			[]flowlogv1.FlowDestination_Provider{
				flowlogv1.FlowDestination_KINESIS, 42, flowlogv1.FlowDestination_AWS_S3, flowlogv1.FlowDestination_KINESIS,
			},
			[]string{flowlog.ProviderS3, flowlog.ProviderKinesis},
		},
		"only unknown": {[]flowlogv1.FlowDestination_Provider{42}, []string{}},
	} {
		// Only unknown types is an empty list, never nil: the store would
		// read nil as S3 and R2.
		if got := destinationTypes(test.named); !slices.Equal(got, test.want) || got == nil {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
	workspaceBytes, networkBytes := testID(1).Bytes(), testID(2).Bytes()
	report, ok := receiverReport(&flowlogv1.FlowStatus{
		InstanceId: bytes.Repeat([]byte{1}, 16), AcceptedVersions: []uint32{1},
		NoiseFingerprints: [][]byte{make([]byte, 32)}, ReportedAtMs: time.Now().UnixMilli(),
		SupportedDestinationTypes: []flowlogv1.FlowDestination_Provider{flowlogv1.FlowDestination_DATADOG},
		Networks: []*flowlogv1.FlowStatus_Network{{
			WorkspaceId: workspaceBytes[:], NetworkId: networkBytes[:], Rejected_24H: 7,
			DeliveryError: flowlogv1.FlowStatus_DELIVERY_EVENT_REJECTED,
		}},
	}, time.Now())
	if !ok || !slices.Equal(report.DestinationTypes, []string{flowlog.ProviderDatadog}) ||
		report.Networks[0].Rejected != 7 || report.Networks[0].DeliveryError != connectionlog.DeliveryEventRejected {
		t.Fatalf("report = %+v %t", report, ok)
	}
}
