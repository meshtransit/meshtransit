package redis

import (
	"context"
	"errors"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
)

const (
	// kubernetesCAMarksPrefix holds, per installation, the highest Kubernetes
	// CA marks the worker saw in the database (a3 §5).
	kubernetesCAMarksPrefix = "meshtransit:v1:kubeca:marks:"
	// kubernetesCAMarksTTL keeps the marks across a year of quiet; each
	// comparison renews it.
	kubernetesCAMarksTTL = 400 * 24 * time.Hour
	// kubernetesCAMarksBand is how much newer than the stored marks a read
	// must be before lower marks count as a restore: two workers that read
	// a moment apart may apply their reads out of order.
	kubernetesCAMarksBand = 10 * time.Second
)

var (
	// ErrKubernetesCAMarks reports an unsafe or failed comparison.
	ErrKubernetesCAMarks = errors.New("redis: kubernetes CA marks")

	// kubernetesCAMarksScript compares the database's marks (ARGV[1]
	// generation, ARGV[2] certificate, ARGV[3] CA; ARGV[4] and ARGV[5] the
	// database's clock in ms before and after it read them) with the stored
	// ones, and returns 1 when the database went back below them. A newer
	// generation (an operator reconciled) or no stored marks takes the
	// database's as they are. "at" is when the read that last raised a mark
	// finished: a read that began a band after it saw everything that read
	// saw, so lower marks then mean a restore; a read that began sooner may
	// have seen less and compares nothing. Only a mark that rises moves "at",
	// so reads that keep coming cannot put the comparison off (review a3a H2,
	// M2). Values are stored as the strings the caller sent.
	kubernetesCAMarksScript = redisclient.NewScript(`
local stored = redis.call('HMGET', KEYS[1], 'generation', 'certificate', 'ca', 'at')
local generation, certificate, ca = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local started, finished = tonumber(ARGV[4]), tonumber(ARGV[5])
local ttl, band = tonumber(ARGV[6]), tonumber(ARGV[7])
local storedGeneration = tonumber(stored[1])
if not storedGeneration or generation > storedGeneration then
  redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'certificate', ARGV[2], 'ca', ARGV[3], 'at', ARGV[5])
  redis.call('PEXPIRE', KEYS[1], ttl)
  return 0
end
local storedCertificate, storedCA, storedAt = tonumber(stored[2]) or 0, tonumber(stored[3]) or 0, tonumber(stored[4]) or 0
if started >= storedAt + band and (generation < storedGeneration or certificate < storedCertificate or ca < storedCA) then
  return 1
end
if generation == storedGeneration and (certificate > storedCertificate or ca > storedCA) then
  if certificate > storedCertificate then redis.call('HSET', KEYS[1], 'certificate', ARGV[2]) end
  if ca > storedCA then redis.call('HSET', KEYS[1], 'ca', ARGV[3]) end
  if finished > storedAt then redis.call('HSET', KEYS[1], 'at', ARGV[5]) end
end
redis.call('PEXPIRE', KEYS[1], ttl)
return 0
`)
)

type kubernetesCAMarksFunc func(ctx context.Context, key string, guard kubeca.Guard) (int64, error)

func runKubernetesCAMarksScript(client *redisclient.Client) kubernetesCAMarksFunc {
	return func(ctx context.Context, key string, guard kubeca.Guard) (int64, error) {
		return kubernetesCAMarksScript.Run(ctx, client, []string{key}, guard.Generation, guard.CertificateMark,
			guard.CAMark, guard.ReadStarted.UnixMilli(), guard.ReadFinished.UnixMilli(),
			kubernetesCAMarksTTL.Milliseconds(), kubernetesCAMarksBand.Milliseconds()).Int64()
	}
}

// Compare implements lifecycle.MarkKeeper: whether the installation's
// database went back below the marks kept here. Losing them (a flush, a
// new Redis) only loses detection until they are seen again.
func (client *Client) Compare(ctx context.Context, installation deployment.ID, guard kubeca.Guard) (bool, error) {
	if ctx == nil || client == nil || client.kubernetesCAMarks == nil || !installation.IsValid() || !guard.Valid() {
		return false, ErrKubernetesCAMarks
	}
	startedAt := time.Now()
	result, err := client.kubernetesCAMarks(ctx, kubernetesCAMarksPrefix+installation.String(), guard)
	client.metrics.observeCommand(redisCommandKubernetesCAMarks, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrKubernetesCAMarks, err)
	}
	switch result {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, ErrKubernetesCAMarks
}
