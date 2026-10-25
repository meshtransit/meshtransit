package identity

import "context"

// PersistHook mirrors a record write somewhere durable outside the state
// directory, such as a Kubernetes Secret for the gateway (k8s-gateway-plan
// §4.3). The store calls it under its lock with the record's file name and
// the exact protected bytes it is about to install, after it has verified
// them and before it renames them into place. An error aborts the write and
// leaves the record on disk as it was. Because the hook runs first, the
// mirror may run ahead of the directory (the install fails after the hook
// succeeded) but never behind it.
//
// The guarantee assumes one Store is the only writer of its directory: the
// check that refuses an existing record on Create covers this process only.
//
// The hook holds the store's lock, so it must bound its own duration; ctx is
// the caller's and may carry no deadline. data is valid only during the call
// and is zeroed after the write: a hook that keeps it must copy it, and it
// must not modify it. The hook must not call back into the store.
type PersistHook func(ctx context.Context, name string, data []byte) error

// Option configures a Store at Open.
type Option func(*Store)

// WithPersistHook calls hook before every record write. A store without one
// writes only to its directory.
func WithPersistHook(hook PersistHook) Option {
	return func(s *Store) { s.persistHook = hook }
}
