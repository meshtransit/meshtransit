package kubeproxy

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// protobufMagic starts every Kubernetes protobuf body, before its
// runtime.Unknown envelope.
var protobufMagic = []byte("k8s\x00")

// protobufMedia is the media type kubectl sends built-in objects in.
const protobufMedia = "application/vnd.kubernetes.protobuf"

// protoFields reads one message's fields by number: each at most once
// (Kubernetes merges repeated messages and keeps the last scalar; the
// gateway refuses both rather than guess), unknown ones skipped, any
// malformed byte refused. A field listed in refuse is refused when present.
func protoFields(message []byte, known map[protowire.Number]protowire.Type,
	refuse ...protowire.Number,
) (map[protowire.Number][]byte, error) {
	fields := map[protowire.Number][]byte{}
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			return nil, errUnevaluable
		}
		message = message[length:]
		size := protowire.ConsumeFieldValue(number, kind, message)
		if size < 0 {
			return nil, errUnevaluable
		}
		value := message[:size]
		message = message[size:]
		for _, refused := range refuse {
			if number == refused {
				return nil, errUnevaluable
			}
		}
		want, isKnown := known[number]
		if !isKnown {
			continue
		}
		if kind != want || want != protowire.BytesType {
			return nil, errUnevaluable
		}
		if _, repeated := fields[number]; repeated {
			return nil, errUnevaluable
		}
		content, n := protowire.ConsumeBytes(value)
		if n < 0 {
			return nil, errUnevaluable
		}
		fields[number] = content
	}
	return fields, nil
}

// protoStrings reads a message of string fields numbered 1 to count; a
// string not valid UTF-8 is refused, as the JSON the gateway forwards could
// not carry it unchanged (review L1).
func protoStrings(message []byte, count int, refuse ...protowire.Number) ([]string, error) {
	known := make(map[protowire.Number]protowire.Type, count)
	for number := 1; number <= count; number++ {
		known[protowire.Number(number)] = protowire.BytesType
	}
	fields, err := protoFields(message, known, refuse...)
	if err != nil {
		return nil, err
	}
	values := make([]string, count)
	for number := 1; number <= count; number++ {
		value := fields[protowire.Number(number)]
		if !utf8.Valid(value) {
			return nil, errUnevaluable
		}
		values[number-1] = string(value)
	}
	return values, nil
}

// decodeAccessReviewProto reads a SelfSubjectAccessReview in Kubernetes
// protobuf, as kubectl sends it: runtime.Unknown{typeMeta{apiVersion, kind},
// raw}, raw a SelfSubjectAccessReview{metadata, spec{resourceAttributes,
// nonResourceAttributes}}. Selectors (fields 8 and 9) cannot be evaluated.
func decodeAccessReviewProto(body []byte, version string) (reviewSpec, error) {
	envelope, found := bytes.CutPrefix(body, protobufMagic)
	if !found {
		return reviewSpec{}, errUnevaluable
	}
	unknown, err := protoFields(envelope, map[protowire.Number]protowire.Type{
		1: protowire.BytesType, 2: protowire.BytesType, 3: protowire.BytesType,
	})
	if err != nil || len(unknown[3]) != 0 {
		return reviewSpec{}, errUnevaluable
	}
	typeMeta, err := protoStrings(unknown[1], 2)
	if err != nil || typeMeta[0] != "authorization.k8s.io/"+version || typeMeta[1] != "SelfSubjectAccessReview" {
		return reviewSpec{}, errUnevaluable
	}
	review, err := protoFields(unknown[2], map[protowire.Number]protowire.Type{2: protowire.BytesType})
	if err != nil {
		return reviewSpec{}, err
	}
	spec, err := protoFields(review[2], map[protowire.Number]protowire.Type{
		1: protowire.BytesType, 2: protowire.BytesType,
	})
	if err != nil {
		return reviewSpec{}, err
	}
	resource, hasResource := spec[1]
	path, hasPath := spec[2]
	switch {
	case hasResource == hasPath:
		return reviewSpec{}, errUnevaluable
	case hasPath:
		values, err := protoStrings(path, 2)
		if err != nil {
			return reviewSpec{}, err
		}
		return reviewSpec{NonResourceAttributes: &reviewPath{Path: values[0], Verb: values[1]}}, nil
	}
	values, err := protoStrings(resource, 7, 8, 9)
	if err != nil {
		return reviewSpec{}, err
	}
	return reviewSpec{ResourceAttributes: &reviewAttributes{
		Namespace: values[0], Verb: values[1],
		Group: values[2], Version: values[3], Resource: values[4], Subresource: values[5], Name: values[6],
	}}, nil
}

// reviewMedia is a review body's media type, lowercased, without
// parameters.
func reviewMedia(contentType string) string {
	media, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(media))
}
