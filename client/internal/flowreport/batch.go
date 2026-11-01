// Package flowreport turns the packet filter's counts into connection log
// batches, keeps them on disk until the receiver commits them, and sends
// them (flowlog-v1 §4–5). MeshTransit stores none of it: the spool is on
// the customer's own machine.
package flowreport

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/shared/flowlog"
)

// ErrBatchTooLarge reports a window whose batch would not fit a request.
var ErrBatchTooLarge = errors.New("flowreport: batch too large")

// Policy is what the counts were taken under.
type Policy struct {
	MapRevision uint64
	Digest      []byte // 32 bytes, or empty when the filter enforces none yet
}

// built is one encoded batch and what the spool keeps about it.
type built struct {
	compressed       []byte
	records          uint64
	fromMS, toMS     int64
	reporterSequence uint64
}

// buildBatch encodes window as batch sequence of boot; it takes window's
// records and may change them. A window longer than the receiver takes
// (twice windowS, after a suspend) keeps its last part and its records are
// clamped into it (flowlog-v1 §6).
func buildBatch(window flowcount.Window, boot [16]byte, sequence uint64, policy Policy,
	windowS uint32,
) (built, error) {
	if len(window.Records) > flowcount.MaxWindowRecords {
		return built{}, ErrBatchTooLarge
	}
	start, end := window.StartMS, window.EndMS
	if span := int64(windowS) * 2000; windowS > 0 && end-start > span {
		start = end - span
	}
	if end <= start {
		end = start + 1
	}
	batch := &flowlogv1.FlowBatch{
		ReporterSequence: sequence, BootId: boot[:], WindowStartMs: start, WindowEndMs: end,
		MapRevision: policy.MapRevision, Records: window.Records,
	}
	if len(policy.Digest) == 32 {
		batch.PolicyDigest = policy.Digest
	}
	for _, record := range batch.Records {
		first := min(max(record.GetFirstSeenMs(), start), end)
		record.FirstSeenMs, record.LastSeenMs = first, min(max(record.GetLastSeenMs(), first), end)
	}
	if overflow := window.Overflow; overflow != (flowcount.Overflow{}) {
		batch.Overflow = &flowlogv1.Overflow{Keys: overflow.Keys, Packets: overflow.Packets, Bytes: overflow.Bytes}
	}
	plain, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		return built{}, fmt.Errorf("flowreport: encode batch: %w", err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		return built{}, fmt.Errorf("flowreport: compress batch: %w", err)
	}
	if err := writer.Close(); err != nil {
		return built{}, fmt.Errorf("flowreport: compress batch: %w", err)
	}
	if compressed.Len() > flowlog.MaxBatchLength || len(plain) > flowlog.MaxBatchSize {
		return built{}, ErrBatchTooLarge
	}
	return built{
		compressed: compressed.Bytes(), records: uint64(len(batch.Records)), fromMS: start, toMS: end,
		reporterSequence: sequence,
	}, nil
}
