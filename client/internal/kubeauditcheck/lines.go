package kubeauditcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errLineTooLong = errors.New("kubeauditcheck: line too long")

// read takes every line of log; a line over limit is streamed.
func (state *checker) read(log io.Reader, limit int) error {
	reader := bufio.NewReaderSize(log, min(limit, readBuffer))
	for number := 1; ; number++ {
		line, err := readLine(reader, limit)
		if errors.Is(err, errLineTooLong) {
			rest := &lineRest{head: line, reader: reader}
			event, decodeErr := decodeLong(rest)
			if _, drainErr := io.Copy(io.Discard, rest); drainErr != nil {
				return fmt.Errorf("reading the audit log: %w", drainErr)
			}
			state.take(event, decodeErr == nil, number)
			if rest.eof {
				return nil
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("reading the audit log: %w", err)
		}
		if len(bytes.TrimSpace(line)) != 0 {
			var event Event
			decodeErr := json.Unmarshal(line, &event)
			state.take(event, decodeErr == nil, number)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

// readLine reads one line. Past limit it stops and returns what it read
// with errLineTooLong; the rest of the line is still in reader.
func readLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
		if len(line) >= limit {
			return line, errLineTooLong
		}
	}
}

// lineRest reads what was read of a line, then the rest of it up to and
// including its newline.
type lineRest struct {
	head   []byte
	buffer []byte
	reader *bufio.Reader
	done   bool
	eof    bool
}

func (rest *lineRest) Read(p []byte) (int, error) {
	if len(rest.head) == 0 {
		if rest.done {
			return 0, io.EOF
		}
		chunk, err := rest.reader.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF):
			rest.done, rest.eof = true, true
		case err != nil:
			return 0, err
		default:
			rest.done = true
		}
		rest.buffer = append(rest.buffer[:0], chunk...)
		rest.head = rest.buffer
		if len(rest.head) == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, rest.head)
	rest.head = rest.head[n:]
	return n, nil
}

// decodeLong reads the fields of an Event from a line too long to hold,
// skipping the request and response objects token by token: memory is
// bounded by the longest value, not the line; the API server's request
// size and etcd's object limit keep a value to a few MiB.
func decodeLong(reader io.Reader) (Event, error) {
	decoder := json.NewDecoder(reader)
	var event Event
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return Event{}, errors.New("kubeauditcheck: not an object")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return Event{}, err
		}
		key, _ := token.(string)
		if field := eventField(&event, key); field != nil {
			err = decoder.Decode(field)
		} else {
			err = skipValue(decoder)
		}
		if err != nil {
			return Event{}, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return Event{}, err
	}
	// Nothing may follow the object, as a line read whole (re-review 3 L2).
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Event{}, errors.New("kubeauditcheck: more than one value on a line")
	}
	return event, nil
}

func eventField(event *Event, key string) any {
	switch key {
	case "kind":
		return &event.Kind
	case "apiVersion":
		return &event.APIVersion
	case "auditID":
		return &event.AuditID
	case "stage":
		return &event.Stage
	case "verb":
		return &event.Verb
	case "requestURI":
		return &event.URI
	case "user":
		return &event.User
	case "impersonatedUser":
		return &event.ImpersonatedUser
	case "objectRef":
		return &event.ObjectRef
	case "requestReceivedTimestamp":
		return &event.Received
	default:
		return nil
	}
}

func skipValue(decoder *json.Decoder) error {
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}
