package app

import "context"

// Service is a process-owned, stoppable component. Done returns the join
// channel after Start succeeds; all work owned by the service ends before Done
// reports its result.
type Service interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	Done() <-chan error
}

// OwnedService gives one lifecycle-owned service a stable diagnostic name.
type OwnedService struct {
	Name    string
	Service Service
}

type startedService struct {
	name    string
	service Service
	done    <-chan error
}
