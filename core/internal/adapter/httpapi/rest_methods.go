package httpapi

import (
	"net/http"
	"slices"
	"strings"
)

// restMethods are the methods one path accepts, in the order the Allow
// header lists them.
type restMethods []string

func (methods restMethods) allows(method string) bool { return slices.Contains(methods, method) }

// allowedMethod returns method when the path accepts it, else "".
func (methods restMethods) allowedMethod(method string) string {
	if methods.allows(method) {
		return method
	}
	return ""
}

func (methods restMethods) header() string { return strings.Join(methods, ", ") }

var (
	collectionMethods = restMethods{http.MethodGet, http.MethodPost}
	itemMethods       = restMethods{http.MethodPatch, http.MethodDelete}
	readMethods       = restMethods{http.MethodGet}
)
