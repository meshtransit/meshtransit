//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
)

// assertRedisKubernetesCAMarks: Redis keeps the highest marks it saw and
// reports a database below them as restored, but not a read too close to
// the last one (two workers may apply reads out of order), and a newer
// generation (an operator reconciled) restarts from the database.
func assertRedisKubernetesCAMarks(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	installation, err := deployment.ParseID(mustPublicID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	read := func(generation, certificate, ca int64, seconds int) kubeca.Guard {
		began := start.Add(time.Duration(seconds) * time.Second)
		return kubeca.Guard{Generation: generation, CertificateMark: certificate, CAMark: ca, ReadStarted: began,
			ReadFinished: began.Add(100 * time.Millisecond)}
	}
	for _, step := range []struct {
		name      string
		guard     kubeca.Guard
		regressed bool
	}{
		{"the first marks", read(1, 10, 20, 0), false},
		{"higher marks", read(1, 12, 21, 30), false},
		// A read that began within the band of the one that raised the
		// marks may have seen less; reads that keep coming do not put the
		// comparison off.
		{"lower marks read a moment later", read(1, 11, 21, 35), false},
		{"lower marks again", read(1, 11, 21, 39), false},
		{"lower certificates past the band", read(1, 11, 21, 41), true},
		{"lower CA versions", read(1, 12, 3, 60), true},
		{"the same marks again", read(1, 12, 21, 60), false},
		{"a reconciled database", read(1761660000000, 1, 1, 90), false},
		{"the generation went back", read(1, 12, 21, 120), true},
		{"after the reconcile", read(1761660000000, 2, 1, 150), false},
	} {
		regressed, err := client.Compare(ctx, installation, step.guard)
		if err != nil || regressed != step.regressed {
			t.Fatalf("%s: Compare() = %v, %v", step.name, regressed, err)
		}
	}
}
