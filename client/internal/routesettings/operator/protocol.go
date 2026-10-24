//go:build linux || darwin

// Package operator lets the members of the meshtransit group change the
// host's own route choices without root: which Exit Pool its Internet
// traffic uses, whether it installs the Site routes Core grants, and whether
// its attached private subnets stay off the exit node. The helper (root)
// owns the socket, checks the caller itself and writes the route settings;
// meshd, which runs unprivileged and talks to Core, still cannot change
// them, so neither can turn the kill switch off (exit node design §11).
//
// Everything else stays root's: what the host serves to others (router mode,
// advertised subnets, exit mode and its limits), public routes, managed exit
// pools, captive portal windows. Root can take the choices back too:
// meshnetd routes operators off.
package operator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is the version every request and response carries.
const ProtocolVersion = 1

// maxMessageBytes bounds one request or response.
const maxMessageBytes = 4 << 10

// Command is what a request asks of the helper.
type Command string

const (
	// CommandShow reads the choices.
	CommandShow Command = "show"
	// CommandExitUse sets the Exit Pool: a pool reference or name,
	// routesettings.ExitUseAuto, or empty for none.
	CommandExitUse Command = "exit-use"
	// CommandAccept turns installing the private Site routes on or off.
	CommandAccept Command = "accept"
	// CommandExitAllowLAN keeps the attached private subnets off the exit
	// node, or not.
	CommandExitAllowLAN Command = "exit-allow-lan"
)

// changes reports whether command changes the settings.
func (command Command) changes() bool {
	switch command {
	case CommandExitUse, CommandAccept, CommandExitAllowLAN:
		return true
	default:
		return false
	}
}

// Request is one command, the only message a connection carries.
type Request struct {
	Version int     `json:"version"`
	Command Command `json:"command"`
	// ExitUse is the pool for CommandExitUse.
	ExitUse string `json:"exit_use,omitempty"`
	// On is the value for CommandAccept and CommandExitAllowLAN.
	On bool `json:"on,omitempty"`
}

// Choices are the settings an operator may see and change.
type Choices struct {
	AcceptRoutes bool   `json:"accept_routes"`
	ExitUse      string `json:"exit_use"`
	ExitAllowLAN bool   `json:"exit_allow_lan"`
	// Operators is whether root lets the meshtransit group change them.
	Operators bool `json:"operators"`
}

// ErrorCode names why the helper refused a request.
type ErrorCode string

const (
	// CodeInvalidRequest is a request that is malformed, or of another version.
	CodeInvalidRequest ErrorCode = "invalid_request"
	// CodeInvalidValue is a value the settings do not accept.
	CodeInvalidValue ErrorCode = "invalid_value"
	// CodeNotPermitted is a caller neither root nor in the group.
	CodeNotPermitted ErrorCode = "not_permitted"
	// CodeOperatorsOff is root keeping the choices (meshnetd routes operators off).
	CodeOperatorsOff ErrorCode = "operators_off"
	// CodeUnavailable is settings the helper could not read or write.
	CodeUnavailable ErrorCode = "unavailable"
	// CodeRootSetting is a change that would also turn on one of root's
	// settings, which root must make.
	CodeRootSetting ErrorCode = "root_setting"
)

// Response answers one request: the choices after it, or why not.
type Response struct {
	Version int       `json:"version"`
	OK      bool      `json:"ok"`
	Error   ErrorCode `json:"error,omitempty"`
	Message string    `json:"message,omitempty"`
	Choices *Choices  `json:"choices,omitempty"`
}

// Error is a refusal the helper sent.
type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("operator: refused (%s)", e.Code)
	}
	return fmt.Sprintf("operator: %s (%s)", e.Message, e.Code)
}

// ErrUnreachable reports a helper socket that cannot be reached: none
// listens, or this user may not connect.
var ErrUnreachable = errors.New("operator: the helper's operator socket is not reachable")

// errTooLarge reports a message past maxMessageBytes.
var errTooLarge = errors.New("operator: message too large")

// encode writes one message as a JSON line.
func encode(writer io.Writer, message any) error {
	encoded, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("operator: encoding: %w", err)
	}
	if len(encoded) >= maxMessageBytes {
		return errTooLarge
	}
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("operator: writing: %w", err)
	}
	return nil
}

// decode reads one JSON line into message, refusing unknown fields,
// trailing data and anything past maxMessageBytes.
func decode(reader io.Reader, message any) error {
	line, err := readLine(reader)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(message); err != nil {
		return fmt.Errorf("operator: decoding: %w", err)
	}
	if decoder.More() {
		return errors.New("operator: trailing data")
	}
	return nil
}

// readLine reads up to the first newline, which it drops.
func readLine(reader io.Reader) ([]byte, error) {
	buffer := make([]byte, 0, 512)
	chunk := make([]byte, 512)
	for {
		count, err := reader.Read(chunk)
		buffer = append(buffer, chunk[:count]...)
		if index := bytes.IndexByte(buffer, '\n'); index >= 0 {
			if index != len(buffer)-1 {
				return nil, errors.New("operator: trailing data")
			}
			return buffer[:index], nil
		}
		if len(buffer) >= maxMessageBytes {
			return nil, errTooLarge
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("operator: reading: %w", err)
		}
	}
}
