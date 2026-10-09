// Package exportformat writes audit exports (R1-64). The formats are part of
// the evidence contract in docs/audit-record-v2.md: a third party verifies an
// export with any implementation of seal v2, such as tools/auditverify,
// without access to MeshCore.
package exportformat

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit/history"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

// Version is the export document version.
const Version = 1

// ErrInvalid reports an export that cannot be written.
var ErrInvalid = errors.New("audit export: invalid export")

// Document is the JSON export. Records are oldest first; Actors names the
// principals who are or were members of the Workspace.
type Document struct {
	ExportVersion int               `json:"export_version"`
	GeneratedAt   string            `json:"generated_at"`
	WorkspaceID   string            `json:"workspace_id"`
	NetworkID     string            `json:"network_id,omitempty"`
	Since         string            `json:"since"`
	Until         string            `json:"until"`
	RecordCount   int               `json:"record_count"`
	Actors        map[string]string `json:"actors"`
	Records       []audit.Record    `json:"Records"`
}

// CSVColumns is the fixed CSV header. Every sealed field is present, so a
// CSV export verifies like the JSON one; actor_name is informative only.
var CSVColumns = []string{
	"event_time", "event_id", "stream_id", "sequence", "workspace_id", "network_id", "change_id",
	"actor_kind", "actor_principal_id", "actor_name", "action", "permission", "result",
	"target_kind", "target_id", "correlation_id", "before_semantic_hash", "after_semantic_hash",
	"payload_version", "payload_canonical", "integrity_status", "hash_version", "previous_seal", "seal",
}

func timeText(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

// NewDocument shapes an export as the JSON document.
func NewDocument(export history.Export) (Document, error) {
	if !export.Query.IsValid() || export.GeneratedAt.IsZero() || export.Records == nil {
		return Document{}, ErrInvalid
	}
	actors := export.Actors
	if actors == nil {
		actors = map[string]string{}
	}
	document := Document{
		ExportVersion: Version, GeneratedAt: timeText(export.GeneratedAt),
		WorkspaceID: export.Query.WorkspaceID.String(), Since: timeText(export.Query.Since),
		Until: timeText(export.Query.Until), RecordCount: len(export.Records), Actors: actors,
		Records: export.Records,
	}
	if export.Query.NetworkID != (network.ID{}) {
		document.NetworkID = export.Query.NetworkID.String()
	}
	return document, nil
}

// WriteJSON writes the JSON document.
func WriteJSON(output io.Writer, export history.Export) error {
	document, err := NewDocument(export)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

// WriteCSV writes the header and one row per record. Sealed cells are never
// rewritten; they cannot start a formula anyway (labels, identifiers, hex and
// payload text that starts with "{"). actor_name is not sealed and comes from
// a person, so a leading formula character is neutralized.
func WriteCSV(output io.Writer, export history.Export) error {
	if !export.Query.IsValid() || export.Records == nil {
		return ErrInvalid
	}
	writer := csv.NewWriter(output)
	if err := writer.Write(CSVColumns); err != nil {
		return err
	}
	for _, record := range export.Records {
		hashVersion := ""
		if record.Integrity.HashVersion != 0 {
			hashVersion = strconv.Itoa(record.Integrity.HashVersion)
		}
		row := []string{
			record.EventTime, record.EventID, record.StreamID, strconv.FormatInt(record.Sequence, 10),
			record.WorkspaceID, record.NetworkID, record.ChangeID, record.ActorKind, record.ActorPrincipalID,
			spreadsheetSafe(export.Actors[record.ActorPrincipalID]), record.Action, record.Permission, record.Result,
			record.TargetKind, record.TargetID, record.CorrelationID, record.BeforeSemanticHash,
			record.AfterSemanticHash, strconv.FormatInt(record.PayloadVersion, 10), record.PayloadCanonical,
			record.Integrity.Status, hashVersion, record.Integrity.PreviousSeal, record.Integrity.Seal,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func spreadsheetSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}
