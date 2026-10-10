package controllistener

import "time"

// Bounds of the public control listener.
const (
	maxHeaderBytes    = 32 << 10
	minTimeout        = 100 * time.Millisecond
	maxHandshake      = 30 * time.Second
	maxSessionTimeout = 5 * time.Minute
	// MaxConnections is the largest per-process connection bound.
	MaxConnections = 4096
)
