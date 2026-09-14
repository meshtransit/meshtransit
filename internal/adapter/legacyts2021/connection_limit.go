package legacyts2021

import (
	"net"
	"sync"
)

// boundedListener limits accepted sockets before TLS and HTTP parsing. Excess
// sockets are closed synchronously; no rejection goroutine or queue is created.
type boundedListener struct {
	net.Listener
	slots     chan struct{}
	telemetry *ControlTelemetry
}

func newBoundedListener(
	listener net.Listener,
	limit int,
	telemetry *ControlTelemetry,
) *boundedListener {
	return &boundedListener{
		Listener:  listener,
		slots:     make(chan struct{}, limit),
		telemetry: telemetry,
	}
}

func (listener *boundedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.slots <- struct{}{}:
			listener.telemetry.connectionOpened()
			return &boundedConnection{
				Conn: connection,
				release: func() {
					<-listener.slots
					listener.telemetry.connectionClosed()
				},
			}, nil
		default:
			listener.telemetry.connectionRejected()
			_ = connection.Close()
		}
	}
}

type boundedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (connection *boundedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}
