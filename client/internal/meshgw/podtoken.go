package meshgw

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
)

// podTokenStaleAfter is how little life a token read may have left before
// the gateway warns. Kubelet rewrites a 600 s token after 80% of it, at its
// next volume sync: 30 to 130 s before exp in a healthy pod (t3 review M1).
// Core ends a session 120 s past its last token's exp (K1c-T §3.2).
const podTokenStaleAfter = 30 * time.Second

// podTokenSource reads the pod token for each session and refresh
// (gateway.token1). An unreadable file sends none, and Core decides; it is
// logged once until the file reads again. A token about to expire, by
// Core's clock, is logged once per token. The token is never logged.
func podTokenSource(path string, logger *slog.Logger, coreNow func() time.Time) func() controlplane.PodToken {
	var mu sync.Mutex
	failing, warned := false, ""
	return func() controlplane.PodToken {
		token, err := daemon.ReadPodToken(path)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if !failing {
				failing = true
				logger.Error("pod token unreadable: sessions go without it", "error_code",
					"kubernetes_pod_token_unavailable", "error", err)
			}
			return ""
		}
		failing = false
		if expiry, ok := tokenExpiry(token); ok && expiry.Sub(coreNow()) < podTokenStaleAfter {
			if signature := tokenSignature(token); signature != warned {
				warned = signature
				logger.Warn("pod token about to expire: kubelet has not refreshed it", "error_code",
					"kubernetes_pod_token_stale", "remaining", expiry.Sub(coreNow()).Round(time.Second).String())
			}
		}
		return token
	}
}

// tokenExpiry reads a JWT's exp without checking it: only to warn.
func tokenExpiry(token controlplane.PodToken) (time.Time, bool) {
	parts := strings.Split(token.Reveal(), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Expiry int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Expiry <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Expiry, 0), true
}

// tokenSignature tells tokens apart without keeping one: its signature
// segment's tail.
func tokenSignature(token controlplane.PodToken) string {
	raw := token.Reveal()
	return raw[max(0, len(raw)-16):]
}
