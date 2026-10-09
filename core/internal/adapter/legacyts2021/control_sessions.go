package legacyts2021

import (
	"context"
	"errors"
	"net"
)

type sessionAdmission uint8

const (
	sessionAdmissionAccepted sessionAdmission = iota
	sessionAdmissionCapacity
	sessionAdmissionShutdown
)

// Shutdown stops session admission, closes every hijacked connection, and
// waits until all synchronous session handlers have returned or ctx expires.
func (server *ControlServer) Shutdown(ctx context.Context) error {
	if server == nil || ctx == nil {
		return ErrInvalidControlServer
	}
	server.mu.Lock()
	server.closing = true
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	drained := server.drained
	server.mu.Unlock()

	var closeErrors []error
	for _, connection := range connections {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	select {
	case <-drained:
		return errors.Join(closeErrors...)
	default:
	}
	select {
	case <-drained:
		return errors.Join(closeErrors...)
	case <-ctx.Done():
		return errors.Join(ErrControlServerShutdown, errors.Join(closeErrors...), ctx.Err())
	}
}

func (server *ControlServer) beginSession() sessionAdmission {
	select {
	case server.slots <- struct{}{}:
	default:
		return sessionAdmissionCapacity
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closing {
		<-server.slots
		return sessionAdmissionShutdown
	}
	if server.active == 0 {
		server.drained = make(chan struct{})
	}
	server.active++
	server.telemetry.sessionSlotOpened()
	return sessionAdmissionAccepted
}

func (server *ControlServer) endSession() {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.active--
	<-server.slots
	server.telemetry.sessionSlotClosed()
	if server.active == 0 {
		close(server.drained)
	}
}

func (server *ControlServer) trackConnection(connection net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closing {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *ControlServer) finishConnection(connection net.Conn) {
	server.mu.Lock()
	defer server.mu.Unlock()
	delete(server.connections, connection)
}

func (server *ControlServer) isClosing() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.closing
}
