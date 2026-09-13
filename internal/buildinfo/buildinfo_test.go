package buildinfo

import "testing"

func TestCurrentAndReleaseDescribeSameBuild(t *testing.T) {
	t.Parallel()

	info := Current()
	if info.Version == "" || info.Revision == "" || info.GoVersion == "" {
		t.Fatalf("Current() = %+v, want complete build metadata", info)
	}
	if got, want := Release(), info.Version+"@"+info.Revision; got != want {
		t.Fatalf("Release() = %q, want %q", got, want)
	}
}
