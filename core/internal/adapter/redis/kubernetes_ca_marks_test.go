package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestClientComparesKubernetesCAMarks(t *testing.T) {
	t.Parallel()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	guard := kubeca.Guard{Generation: 2, CertificateMark: 10, CAMark: 30, ReadStarted: time.Now(), ReadFinished: time.Now()}
	for name, test := range map[string]struct {
		result    int64
		err       error
		regressed bool
		fails     bool
	}{
		"kept":      {result: 0},
		"went back": {result: 1, regressed: true},
		"unknown":   {result: 2, fails: true},
		"redis":     {err: errors.New("down"), fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &Client{kubernetesCAMarks: func(_ context.Context, key string,
				got kubeca.Guard,
			) (int64, error) {
				if key != kubernetesCAMarksPrefix+installation.String() || got != guard {
					t.Errorf("script got %q, %+v", key, got)
				}
				return test.result, test.err
			}}
			regressed, err := client.Compare(t.Context(), installation, guard)
			if regressed != test.regressed || (err != nil) != test.fails ||
				test.fails && !errors.Is(err, ErrKubernetesCAMarks) {
				t.Fatalf("Compare() = %v, %v", regressed, err)
			}
		})
	}
	client := &Client{}
	if _, err := client.Compare(t.Context(), installation, kubeca.Guard{}); !errors.Is(err, ErrKubernetesCAMarks) {
		t.Fatalf("Compare(invalid) = %v", err)
	}
}
