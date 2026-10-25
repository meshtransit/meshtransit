package profile

import "context"

// PersistHook mirrors a profile state write somewhere durable outside the
// state directory, such as a Kubernetes Secret for the gateway
// (k8s-gateway-plan §4.3). The store calls it under its lock with the state
// file's name and the exact bytes it is about to install, before it renames
// them into place. An error aborts the write and leaves the file and the
// store's state as they were. Because the hook runs first, the mirror may run
// ahead of the directory (the install fails after the hook succeeded) but
// never behind it. The guarantee assumes one Store is the only writer of its
// directory.
//
// The hook holds the store's lock, which also blocks readers, so it must
// bound its own duration; ctx is the caller's and may carry no deadline. data
// is valid only during the call: a hook that keeps it must copy it, and it
// must not modify it. The hook must not call back into the store.
type PersistHook func(ctx context.Context, name string, data []byte) error

// Option configures a Store at Open.
type Option func(*Store)

// WithPersistHook calls hook before every state write. A store without one
// writes only to its directory.
func WithPersistHook(hook PersistHook) Option {
	return func(s *Store) { s.persistHook = hook }
}
