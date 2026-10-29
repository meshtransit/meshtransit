package mtcp

// gateway.audit1 bounds (mtcp-v1 §6.10).
const (
	// KubeAuditBatchIDSize is the size of a batch ID.
	KubeAuditBatchIDSize = 16
	// KubeAuditIntentIDSize is the size of an intent ID, in the UUIDv7
	// layout.
	KubeAuditIntentIDSize = 16
)
