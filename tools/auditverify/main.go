// Command auditverify checks a MeshTransit audit export without MeshCore.
//
// It recomputes seal v2 for every sealed record, checks that each audit
// stream in the export is a contiguous run of sequence numbers, and that
// every sealed record links to the seal of the record before it. It uses
// only the Go standard library and implements the seal from the
// specification in docs/audit-record-v2.md, not from MeshCore code, so it
// can be reviewed and rebuilt by the party that holds the export.
//
// Usage:
//
//	auditverify [-format json|csv] export-file
//
// Exit status is 0 when everything verifies, 1 when any check fails and 2
// for a usage or read error.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sealDomain   = "meshtransit/audit-event/v2\x00"
	timeLayout   = "2006-01-02T15:04:05.000000Z"
	maximumBytes = 64 << 20
	sealed       = "sealed"
	legacy       = "legacy_unsealed"
)

// record holds the fields seal v2 covers, as exported.
type record struct {
	EventID            string `json:"event_id"`
	EventTime          string `json:"event_time"`
	StreamID           string `json:"stream_id"`
	Sequence           int64  `json:"sequence"`
	WorkspaceID        string `json:"workspace_id"`
	NetworkID          string `json:"network_id"`
	ChangeID           string `json:"change_id"`
	ActorPrincipalID   string `json:"actor_principal_id"`
	Action             string `json:"action"`
	Permission         string `json:"permission"`
	Result             string `json:"result"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id"`
	CorrelationID      string `json:"correlation_id"`
	BeforeSemanticHash string `json:"before_semantic_hash"`
	AfterSemanticHash  string `json:"after_semantic_hash"`
	PayloadVersion     int64  `json:"payload_version"`
	PayloadCanonical   string `json:"payload_canonical"`
	Integrity          struct {
		Status       string `json:"status"`
		HashVersion  int    `json:"hash_version"`
		PreviousSeal string `json:"previous_seal"`
		Seal         string `json:"seal"`
	} `json:"integrity"`
}

type document struct {
	ExportVersion int      `json:"export_version"`
	RecordCount   int      `json:"record_count"`
	Records       []record `json:"Records"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("auditverify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "", "export format: json or csv (default: from the file name)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: auditverify [-format json|csv] export-file")
		return 2
	}
	path := flags.Arg(0)
	if *format == "" {
		*format = "json"
		if strings.HasSuffix(strings.ToLower(path), ".csv") {
			*format = "csv"
		}
	}
	content, err := readBounded(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditverify: %v\n", err)
		return 2
	}
	var records []record
	switch *format {
	case "json":
		records, err = parseJSON(content)
	case "csv":
		records, err = parseCSV(content)
	default:
		err = errors.New("format must be json or csv")
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditverify: %v\n", err)
		return 2
	}
	report := verify(records)
	report.write(stdout)
	if len(report.failures) > 0 {
		return 1
	}
	return 0
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the operator names the export file to verify.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maximumBytes {
		return nil, errors.New("export is larger than 64 MiB")
	}
	return content, nil
}

func parseJSON(content []byte) ([]record, error) {
	var parsed document
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("read JSON export: %w", err)
	}
	if parsed.ExportVersion != 1 {
		return nil, fmt.Errorf("unsupported export_version %d", parsed.ExportVersion)
	}
	if parsed.RecordCount != len(parsed.Records) {
		return nil, fmt.Errorf("record_count %d but %d records", parsed.RecordCount, len(parsed.Records))
	}
	return parsed.Records, nil
}

var csvColumns = []string{
	"event_time", "event_id", "stream_id", "sequence", "workspace_id", "network_id", "change_id",
	"actor_kind", "actor_principal_id", "actor_name", "action", "permission", "result",
	"target_kind", "target_id", "correlation_id", "before_semantic_hash", "after_semantic_hash",
	"payload_version", "payload_canonical", "integrity_status", "hash_version", "previous_seal", "seal",
}

func parseCSV(content []byte) ([]record, error) {
	reader := csv.NewReader(bytes.NewReader(content))
	reader.FieldsPerRecord = len(csvColumns)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read CSV export: %w", err)
	}
	if len(rows) == 0 || strings.Join(rows[0], ",") != strings.Join(csvColumns, ",") {
		return nil, errors.New("CSV header does not match the export format")
	}
	records := make([]record, 0, len(rows)-1)
	for index, row := range rows[1:] {
		var item record
		var sequenceErr, versionErr, hashErr error
		item.EventTime, item.EventID, item.StreamID = row[0], row[1], row[2]
		item.Sequence, sequenceErr = strconv.ParseInt(row[3], 10, 64)
		item.WorkspaceID, item.NetworkID, item.ChangeID = row[4], row[5], row[6]
		item.ActorPrincipalID, item.Action, item.Permission, item.Result = row[8], row[10], row[11], row[12]
		item.TargetKind, item.TargetID, item.CorrelationID = row[13], row[14], row[15]
		item.BeforeSemanticHash, item.AfterSemanticHash = row[16], row[17]
		item.PayloadVersion, versionErr = strconv.ParseInt(row[18], 10, 64)
		item.PayloadCanonical, item.Integrity.Status = row[19], row[20]
		if row[21] != "" {
			item.Integrity.HashVersion, hashErr = strconv.Atoi(row[21])
		}
		item.Integrity.PreviousSeal, item.Integrity.Seal = row[22], row[23]
		if err := errors.Join(sequenceErr, versionErr, hashErr); err != nil {
			return nil, fmt.Errorf("CSV row %d: %w", index+2, err)
		}
		records = append(records, item)
	}
	return records, nil
}

// field appends one length-delimited field: 8-byte big-endian length, bytes.
func field(output, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	return append(append(output, length[:]...), value...)
}

func integer(value int64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value)) //nolint:gosec // G115: two's complement, as specified.
	return encoded[:]
}

// uuidBytes returns the 16 bytes of a canonical UUID, or nil when absent.
func uuidBytes(text string, optional bool) ([]byte, error) {
	if text == "" && optional {
		return nil, nil
	}
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' ||
		strings.ToLower(text) != text {
		return nil, fmt.Errorf("malformed UUID %q", text)
	}
	value, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil {
		return nil, fmt.Errorf("malformed UUID %q", text)
	}
	return value, nil
}

func hashBytes(text string, optional bool) ([]byte, error) {
	if text == "" && optional {
		return nil, nil
	}
	value, err := hex.DecodeString(text)
	if err != nil || len(value) != sha256.Size || strings.ToLower(text) != text {
		return nil, fmt.Errorf("malformed hash %q", text)
	}
	return value, nil
}

// seal recomputes seal v2 of one record.
func seal(item record) ([]byte, error) {
	occurred, err := time.Parse(timeLayout, item.EventTime)
	if err != nil {
		return nil, fmt.Errorf("malformed event_time %q", item.EventTime)
	}
	if item.Sequence <= 0 || item.PayloadVersion <= 0 || item.Action == "" || item.Permission == "" ||
		item.TargetKind == "" || item.Result == "" || item.PayloadCanonical == "" {
		return nil, errors.New("required field is missing")
	}
	type part struct {
		text     string
		optional bool
	}
	encoded := []byte(sealDomain)
	previous, err := hashBytes(item.Integrity.PreviousSeal, false)
	if err != nil {
		return nil, err
	}
	encoded = field(encoded, previous)
	stream, err := uuidBytes(item.StreamID, false)
	if err != nil {
		return nil, err
	}
	encoded = field(field(encoded, stream), integer(item.Sequence))
	event, err := uuidBytes(item.EventID, false)
	if err != nil {
		return nil, err
	}
	encoded = field(field(encoded, event), integer(occurred.UnixMicro()))
	for _, value := range []part{{item.WorkspaceID, true}, {item.NetworkID, true},
		{item.ChangeID, false}, {item.ActorPrincipalID, true}} {
		decoded, err := uuidBytes(value.text, value.optional)
		if err != nil {
			return nil, err
		}
		encoded = field(encoded, decoded)
	}
	encoded = field(field(field(encoded, []byte(item.Action)), []byte(item.Permission)), []byte(item.TargetKind))
	target, err := uuidBytes(item.TargetID, false)
	if err != nil {
		return nil, err
	}
	encoded = field(field(encoded, target), []byte(item.Result))
	correlation, err := uuidBytes(item.CorrelationID, true)
	if err != nil {
		return nil, err
	}
	encoded = field(encoded, correlation)
	for _, value := range []string{item.BeforeSemanticHash, item.AfterSemanticHash} {
		decoded, err := hashBytes(value, true)
		if err != nil {
			return nil, err
		}
		encoded = field(encoded, decoded)
	}
	encoded = field(field(encoded, integer(item.PayloadVersion)), []byte(item.PayloadCanonical))
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

type streamReport struct {
	id                   string
	first, last          int64
	sealedCount, legacy  int
	firstSealed          int64
	firstSealedIsGenesis bool
}

type report struct {
	records  int
	streams  []streamReport
	failures []string
}

func verify(records []record) report {
	result := report{records: len(records)}
	byStream := map[string][]record{}
	for _, item := range records {
		byStream[item.StreamID] = append(byStream[item.StreamID], item)
	}
	ids := make([]string, 0, len(byStream))
	for id := range byStream {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	zero := strings.Repeat("00", sha256.Size)
	for _, id := range ids {
		items := byStream[id]
		sort.Slice(items, func(left, right int) bool { return items[left].Sequence < items[right].Sequence })
		stream := streamReport{id: id, first: items[0].Sequence, last: items[len(items)-1].Sequence}
		fail := func(format string, args ...any) {
			result.failures = append(result.failures, fmt.Sprintf("stream %s: ", id)+fmt.Sprintf(format, args...))
		}
		for index, item := range items {
			if index > 0 && item.Sequence != items[index-1].Sequence+1 {
				if item.Sequence == items[index-1].Sequence {
					fail("sequence #%d appears twice", item.Sequence)
				} else {
					fail("events #%d to #%d are missing", items[index-1].Sequence+1, item.Sequence-1)
				}
			}
			switch item.Integrity.Status {
			case legacy:
				stream.legacy++
				if index > 0 && items[index-1].Integrity.Status == sealed {
					fail("#%d is unsealed after sealed events", item.Sequence)
				}
				continue
			case sealed:
			default:
				fail("#%d has unknown integrity status %q", item.Sequence, item.Integrity.Status)
				continue
			}
			if item.Integrity.HashVersion != 2 {
				fail("#%d has unsupported hash_version %d", item.Sequence, item.Integrity.HashVersion)
				continue
			}
			computed, err := seal(item)
			if err != nil {
				fail("#%d cannot be sealed: %v", item.Sequence, err)
				continue
			}
			if hex.EncodeToString(computed) != item.Integrity.Seal {
				fail("#%d seal does not match its fields (the record was changed)", item.Sequence)
			}
			if stream.sealedCount == 0 {
				stream.firstSealed = item.Sequence
				stream.firstSealedIsGenesis = item.Integrity.PreviousSeal == zero
			} else if previous := items[index-1]; previous.Integrity.Status == sealed &&
				item.Integrity.PreviousSeal != previous.Integrity.Seal {
				fail("#%d does not link to the seal of #%d", item.Sequence, previous.Sequence)
			}
			stream.sealedCount++
		}
		result.streams = append(result.streams, stream)
	}
	return result
}

func (result report) write(output io.Writer) {
	_, _ = fmt.Fprintf(output, "records: %d in %d streams\n", result.records, len(result.streams))
	for _, stream := range result.streams {
		line := fmt.Sprintf("stream %s: #%d-#%d, %d sealed, %d before sealing", stream.id, stream.first,
			stream.last, stream.sealedCount, stream.legacy)
		switch {
		case stream.sealedCount == 0:
		case stream.firstSealedIsGenesis:
			line += fmt.Sprintf("; sealing starts at #%d", stream.firstSealed)
		default:
			line += fmt.Sprintf("; #%d continues a chain from before this export", stream.firstSealed)
		}
		_, _ = fmt.Fprintln(output, line)
	}
	if len(result.failures) == 0 {
		_, _ = fmt.Fprintln(output, "result: VERIFIED")
		return
	}
	for _, failure := range result.failures {
		_, _ = fmt.Fprintln(output, "FAIL "+failure)
	}
	_, _ = fmt.Fprintf(output, "result: FAILED (%d problems)\n", len(result.failures))
}
