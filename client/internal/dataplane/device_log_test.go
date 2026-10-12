//go:build linux || darwin || windows

package dataplane

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func decodeDeviceLogs(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decoding %q: %v", line, err)
		}
		records = append(records, record)
	}

	return records
}

func TestDeviceLoggerRedactsAddressesAndLimitsRepeats(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	now := time.Unix(1_800_000_000, 0)
	logger := newDeviceLogger(
		slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})),
		func() time.Time { return now },
	)
	const sendFailure = "%v - Failed to send data packets: %v"
	sendErr := "write udp 0.0.0.0:41641->203.0.113.20:41641: sendto: no route to host"
	logger.Errorf(sendFailure, "peer(AbCd…WxYz)", sendErr)
	logger.Errorf(sendFailure, "peer(AbCd…WxYz)", sendErr)
	logger.Verbosef("Failed to receive %s packet: %v", "v6", "read udp [2001:db8::1]:41641: host is down")
	logger.Verbosef("Routine: receive incoming %s - stopped", "v4")
	now = now.Add(deviceLogInterval + time.Second)
	logger.Errorf(sendFailure, "peer(AbCd…WxYz)", sendErr)

	records := decodeDeviceLogs(t, &output)
	if len(records) != 3 {
		t.Fatalf("records = %v, want 3", records)
	}
	for _, record := range records {
		detail, _ := record["detail"].(string)
		if strings.Contains(detail, "203.0.113.20") || strings.Contains(detail, "2001:db8") ||
			strings.Contains(detail, "0.0.0.0") {
			t.Fatalf("detail %q carries an address", detail)
		}
	}
	first, _ := records[0]["detail"].(string)
	if records[0]["level"] != "WARN" || !strings.Contains(first, "<addr>:41641") {
		t.Fatalf("first record = %v", records[0])
	}
	receive, _ := records[1]["detail"].(string)
	if records[1]["level"] != "INFO" || !strings.Contains(receive, "Failed to receive v6") {
		t.Fatalf("receive record = %v", records[1])
	}
	if records[2]["suppressed"] != float64(1) {
		t.Fatalf("repeat record = %v, want suppressed=1", records[2])
	}
}

func TestDeviceLoggerWithoutLoggerDiscards(t *testing.T) {
	t.Parallel()

	logger := newDeviceLogger(nil, time.Now)
	logger.Errorf("Failed to read packet from TUN device: %v", "boom")
	logger.Verbosef("Failed to receive %s packet: %v", "v4", "boom")
}
