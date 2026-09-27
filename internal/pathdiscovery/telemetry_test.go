package pathdiscovery

import "testing"

func TestProbeTelemetrySnapshotIsAggregateAndMonotonic(t *testing.T) {
	t.Parallel()

	telemetry := NewProbeTelemetry()
	telemetry.RecordMapActivation()
	telemetry.RecordActivationPreserved(2)
	telemetry.RecordActivationRetired(1)
	telemetry.RecordPendingInvalidated(3)
	telemetry.RecordRoundStarted()
	telemetry.RecordRoundCompleted()
	telemetry.RecordProbeAttempt()
	telemetry.RecordProbeStarted()
	telemetry.RecordProbeSent()
	telemetry.RecordProbeStartFailure()
	telemetry.RecordProbeSendFailure()
	telemetry.RecordDatagramDrop()
	telemetry.RecordAuthenticatedPing()
	telemetry.RecordPingRateLimited()
	telemetry.RecordPongSent()
	telemetry.RecordPongSendFailure()
	telemetry.RecordAuthenticatedPong()
	telemetry.RecordProbeCompletion()
	telemetry.RecordCompletionRejection()
	telemetry.RecordObservationQueued()
	telemetry.RecordObservationDropped()
	telemetry.RecordObservationAccepted()
	telemetry.RecordObservationRejected()
	telemetry.RecordDirectExpiry(4)

	want := ProbeTelemetrySnapshot{
		MapActivations:       1,
		ActivationPreserved:  2,
		ActivationRetired:    1,
		PendingInvalidated:   3,
		RoundsStarted:        1,
		RoundsCompleted:      1,
		ProbeAttempts:        1,
		ProbesStarted:        1,
		ProbesSent:           1,
		ProbeStartFailures:   1,
		ProbeSendFailures:    1,
		DatagramDrops:        1,
		AuthenticatedPings:   1,
		PingRateLimited:      1,
		PongsSent:            1,
		PongSendFailures:     1,
		AuthenticatedPongs:   1,
		ProbeCompletions:     1,
		CompletionRejections: 1,
		ObservationsQueued:   1,
		ObservationDrops:     1,
		ObservationsAccepted: 1,
		ObservationRejected:  1,
		DirectExpirations:    4,
	}
	if got := telemetry.Snapshot(); got != want {
		t.Fatalf("Snapshot() = %#v, want %#v", got, want)
	}
}
