package postgres

// PoolRole identifies the fixed PostgreSQL credential boundary represented by
// a serving pool. It is safe to use as a bounded metrics label.
type PoolRole string

const (
	// PoolRoleRuntime serves API and control-plane reads and writes.
	PoolRoleRuntime PoolRole = "runtime"
	// PoolRoleWorker serves background delivery work.
	PoolRoleWorker PoolRole = "worker"
)

func (role PoolRole) valid() bool {
	return role == PoolRoleRuntime || role == PoolRoleWorker
}

func (role PoolRole) applicationName() string {
	if !role.valid() {
		return ""
	}
	return "meshcore-" + string(role)
}
