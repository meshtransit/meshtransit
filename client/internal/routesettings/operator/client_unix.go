//go:build linux || darwin

package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Do sends request to the helper's operator socket and returns the choices
// after it. A refusal is an *Error.
func Do(ctx context.Context, socketPath string, request Request) (Choices, error) {
	request.Version = ProtocolVersion
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Choices{}, fmt.Errorf("%w: %s: %w", ErrUnreachable, socketPath, err)
	}
	defer func() { _ = connection.Close() }()
	// The context ends the exchange itself, so its error is the one seen.
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := encode(connection, request); err != nil {
		return Choices{}, contextError(ctx, err)
	}
	var response Response
	if err := decode(connection, &response); err != nil {
		return Choices{}, contextError(ctx, err)
	}
	if response.Version != ProtocolVersion {
		return Choices{}, errors.New("operator: the helper speaks another protocol version")
	}
	if !response.OK {
		return Choices{}, &Error{Code: response.Error, Message: response.Message}
	}
	if response.Choices == nil {
		return Choices{}, errors.New("operator: the helper sent no settings")
	}
	return *response.Choices, nil
}

// contextError prefers the context's error once it ended.
func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
