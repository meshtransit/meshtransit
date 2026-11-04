package selfhost

import "strings"

// tunableSettings are the only settings config.yaml's advanced: may set:
// timeouts, intervals, limits and pool sizes that change capacity, never
// trust, identity, addresses, keys or anything that must match across
// processes. Identity tunables are left out because they are part of the
// approved broker fingerprint. Anything not listed is refused (fail closed).
var tunableSettings = map[string]bool{
	"MESHTRANSIT_LOG_LEVEL":                               true,
	"MESHTRANSIT_SHUTDOWN_TIMEOUT":                        true,
	"MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL":               true,
	"MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT":                true,
	"MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS":             true,
	"MESHTRANSIT_API_MAX_CONNECTIONS":                     true,
	"MESHTRANSIT_API_REQUEST_TIMEOUT":                     true,
	"MESHTRANSIT_API_SESSION_RATE_LIMIT_CAPACITY":         true,
	"MESHTRANSIT_API_SESSION_RATE_LIMIT_REFILL_INTERVAL":  true,
	"MESHTRANSIT_API_SOURCE_RATE_LIMIT_CAPACITY":          true,
	"MESHTRANSIT_API_SOURCE_RATE_LIMIT_REFILL_INTERVAL":   true,
	"MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT":               true,
	"MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT":        true,
	"MESHTRANSIT_CONTROL_MAP_ENDPOINT_ANNOUNCE_INTERVAL":  true,
	"MESHTRANSIT_CONTROL_MAP_INVENTORY_STATEMENT_TIMEOUT": true,
	"MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL":          true,
	"MESHTRANSIT_CONTROL_MAP_PEER_LIMIT":                  true,
	"MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL":          true,
	"MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT":             true,
	"MESHTRANSIT_CONTROL_MAP_SHARE_STATEMENT_TIMEOUT":     true,
	"MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT":           true,
	"MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT":      true,
	"MESHTRANSIT_CONTROL_MAX_SESSIONS":                    true,
	"MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION":         true,
	"MESHTRANSIT_CONTROL_MTCP_UNPROVEN_SESSION_LIFETIME":  true,
	"MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT":               true,
	"MESHTRANSIT_CONTROL_REBALANCE_INTERVAL":              true,
	"MESHTRANSIT_MAIL_TIMEOUT":                            true,
	"MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE":             true,
	"MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT":      true,
	"MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL":          true,
	"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS":        true,
	"MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS":         true,
	"MESHTRANSIT_REDIS_POOL_SIZE":                         true,
	"MESHTRANSIT_REGISTRATION_ADDRESS_CANDIDATE_LIMIT":    true,
	"MESHTRANSIT_REGISTRATION_IDLE_TIMEOUT":               true,
	"MESHTRANSIT_REGISTRATION_LOCK_TIMEOUT":               true,
	"MESHTRANSIT_REGISTRATION_MAX_ATTEMPTS":               true,
	"MESHTRANSIT_REGISTRATION_ROLLBACK_TIMEOUT":           true,
	"MESHTRANSIT_REGISTRATION_STATEMENT_TIMEOUT":          true,
}

func tunableSetting(name string) bool { return tunableSettings[name] }

// safeEnvValue accepts what compose's env_file passes through unchanged and
// Core's loader reads the same way: no expansion ($), quoting, escaping or
// comment (#) characters, no surrounding spaces, one printable line.
func safeEnvValue(value string) bool {
	return validValue(value, 0, maximumValueBytes) && !strings.ContainsAny(value, "$\"'`\\#") &&
		strings.TrimSpace(value) == value
}
