//go:build windows && (amd64 || arm64)

package winfw

import (
	"errors"
	"syscall"
	"testing"
)

func TestFWPResultReadsTheLow32Bits(t *testing.T) {
	if err := fwpResult(0xffffffff00000000); err != nil {
		t.Fatalf("a zero DWORD is success, got %v", err)
	}
	err := fwpResult(0xffffffff00000000 | fwpErrorFilterNotFound)
	if !errors.Is(err, syscall.Errno(fwpErrorFilterNotFound)) {
		t.Fatalf("fwpResult = %v, want filter not found", err)
	}
}
