package runtimehealth

import "testing"

func TestRead(t *testing.T) {
	t.Parallel()

	snapshot := Read()
	if snapshot.Goroutines == 0 {
		t.Fatal("Read() reported no goroutines")
	}
	if snapshot.HeapAllocBytes == 0 || snapshot.HeapInUseBytes == 0 ||
		snapshot.HeapObjects == 0 || snapshot.StackInUseBytes == 0 ||
		snapshot.SysBytes == 0 {
		t.Fatalf("Read() returned an incomplete memory snapshot: %#v", snapshot)
	}
	if snapshot.HeapAllocBytes > snapshot.HeapInUseBytes {
		t.Fatalf(
			"Read() heap allocation = %d, exceeds heap in-use = %d",
			snapshot.HeapAllocBytes,
			snapshot.HeapInUseBytes,
		)
	}
}
