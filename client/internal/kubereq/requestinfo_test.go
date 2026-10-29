/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified by The MeshTransit Authors: the tables of
k8s.io/apiserver@v0.35.1 pkg/endpoints/request/requestinfo_test.go, run
against Parse; field and label selectors are not kept (K1b design §5).
*/

package kubereq

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func parseURL(t *testing.T, method, raw string) (Info, error) {
	t.Helper()
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	return Parse(method, target)
}

func TestParseResourceRequests(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method, url                                       string
		verb, prefix, group, version, namespace, resource string
		subresource, name                                 string
		parts                                             []string
	}{
		// resource paths
		{http.MethodGet, "/api/v1/namespaces", "list", "api", "", "v1", "", "namespaces", "", "", []string{"namespaces"}},
		{http.MethodGet, "/api/v1/namespaces/other", "get", "api", "", "v1", "other", "namespaces", "", "other", []string{"namespaces", "other"}},
		{http.MethodGet, "/api/v1/namespaces/other/pods", "list", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/namespaces/other/pods/foo", "get", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo"}},
		{http.MethodHead, "/api/v1/namespaces/other/pods/foo", "get", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo"}},
		{http.MethodGet, "/api/v1/pods", "list", "api", "", "v1", "", "pods", "", "", []string{"pods"}},
		{http.MethodHead, "/api/v1/pods", "list", "api", "", "v1", "", "pods", "", "", []string{"pods"}},
		// special verbs
		{http.MethodGet, "/api/v1/proxy/namespaces/other/pods/foo", "proxy", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo"}},
		{http.MethodGet, "/api/v1/proxy/namespaces/other/pods/foo/subpath/not/a/subresource", "proxy", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo", "subpath", "not", "a", "subresource"}},
		{http.MethodGet, "/api/v1/watch/pods", "watch", "api", "", "v1", "", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/pods?watch=true", "watch", "api", "", "v1", "", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/pods?watch=false", "list", "api", "", "v1", "", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/watch/namespaces/other/pods", "watch", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/namespaces/other/pods?watch=1", "watch", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		{http.MethodGet, "/api/v1/namespaces/other/pods?watch=0", "list", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		// subresource identification
		{http.MethodGet, "/api/v1/namespaces/other/pods/foo/status", "get", "api", "", "v1", "other", "pods", "status", "foo", []string{"pods", "foo", "status"}},
		{http.MethodGet, "/api/v1/namespaces/other/pods/foo/proxy/subpath", "get", "api", "", "v1", "other", "pods", "proxy", "foo", []string{"pods", "foo", "proxy", "subpath"}},
		{http.MethodPut, "/api/v1/namespaces/other/finalize", "update", "api", "", "v1", "other", "namespaces", "finalize", "other", []string{"namespaces", "other", "finalize"}},
		{http.MethodPut, "/api/v1/namespaces/other/status", "update", "api", "", "v1", "other", "namespaces", "status", "other", []string{"namespaces", "other", "status"}},
		// verb identification
		{http.MethodPatch, "/api/v1/namespaces/other/pods/foo", "patch", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo"}},
		{http.MethodDelete, "/api/v1/namespaces/other/pods/foo", "delete", "api", "", "v1", "other", "pods", "", "foo", []string{"pods", "foo"}},
		{http.MethodPost, "/api/v1/namespaces/other/pods", "create", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		// deletecollection verb identification
		{http.MethodDelete, "/api/v1/nodes", "deletecollection", "api", "", "v1", "", "nodes", "", "", []string{"nodes"}},
		{http.MethodDelete, "/api/v1/namespaces", "deletecollection", "api", "", "v1", "", "namespaces", "", "", []string{"namespaces"}},
		{http.MethodDelete, "/api/v1/namespaces/other/pods", "deletecollection", "api", "", "v1", "other", "pods", "", "", []string{"pods"}},
		{http.MethodDelete, "/apis/extensions/v1/namespaces/other/pods", "deletecollection", "apis", "extensions", "v1", "other", "pods", "", "", []string{"pods"}},
		// api group and version identification
		{http.MethodPost, "/apis/extensions/v1/namespaces/other/pods", "create", "apis", "extensions", "v1", "other", "pods", "", "", []string{"pods"}},
		{http.MethodPost, "/apis/extensions/v1beta3/namespaces/other/pods", "create", "apis", "extensions", "v1beta3", "other", "pods", "", "", []string{"pods"}},
	} {
		got, err := parseURL(t, test.method, test.url)
		if err != nil {
			t.Errorf("%s %s: error %v", test.method, test.url, err)
			continue
		}
		want := Info{IsResourceRequest: true, Verb: test.verb, APIPrefix: test.prefix, APIGroup: test.group,
			APIVersion: test.version, Namespace: test.namespace, Resource: test.resource,
			Subresource: test.subresource, Name: test.name, Parts: test.parts}
		got.Path = ""
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s:\n got %+v\nwant %+v", test.method, test.url, got, want)
		}
	}
}

func TestParseNonResourceRequests(t *testing.T) {
	t.Parallel()
	for name, path := range map[string]string{
		"no resource path": "/", "just apiversion": "/api/version/", "just prefix, group, version": "/apis/group/version/",
		"bad prefix": "/badprefix/version/resource", "missing api group": "/apis/version/resource",
		"group without enough steps": "/apis/extensions/v1beta1", "not enough steps": "/api/version",
		"one step": "/api", "empty": "",
	} {
		got, err := parseURL(t, http.MethodGet, path)
		if err != nil || got.IsResourceRequest {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	for name, path := range map[string]string{
		"simple groupless": "/api/version/resource", "simple group": "/apis/group/version/resource/name/subresource",
		"group list": "/apis/batch/v1/job", "group subresource": "/apis/batch/v1/job/foo/scale",
	} {
		if got, err := parseURL(t, http.MethodGet, path); err != nil || !got.IsResourceRequest {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// A special verb without a resource cannot be told apart.
	if _, err := parseURL(t, http.MethodGet, "/api/v1/watch"); err == nil {
		t.Error("a watch without a resource parsed")
	}
}

// The name of a list or watch comes from an exact metadata.name field
// selector, unless the selector, or the list options, do not parse.
func TestParseFieldSelectorName(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method, url, verb, name string
	}{
		{http.MethodGet, "/apis/group/version/resource", "list", ""},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=metadata.name=name1", "list", "name1"},
		{http.MethodGet, "/apis/group/version/resource?watch=true&fieldSelector=metadata.name=name1", "watch", "name1"},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=foo=bar", "list", ""},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=metadata.name=name1,foo", "list", ""},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=metadata.name=name1,foo&watch=true", "watch", ""},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=metadata.name=name1,foo&watch=false", "list", ""},
		{http.MethodDelete, "/apis/group/version/resource?fieldSelector=foo=bar", "deletecollection", ""},
		{http.MethodGet, "/apis/group/version/resource?fieldSelector=metadata.name=foo&fieldSelector=metadata.name=bar", "list", "foo"},
		{http.MethodGet, "/apis/group/version/resource/name?fieldSelector=foo=bar", "get", "name"},
		{http.MethodGet, "/apis/group/version/watch/resource?fieldSelector=metadata.name=foo", "watch", ""},
		{http.MethodGet, "/apis/group/version/watch/resource/name?fieldSelector=metadata.name=foo", "watch", "name"},
		// MeshTransit additions, by apimachinery's rules.
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3D%3Ddb", "list", "db"},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name!%3Ddb", "list", ""},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=a%3Db,metadata.name%3Dx", "list", "x"},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Da%5C,b", "list", "a,b"}, // an escaped ","
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Da%5Cx", "list", ""},     // a bad escape
		// A label selector is not parsed here: a name is kept only without one.
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Dx&labelSelector=a%3Db", "list", ""},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3D..", "list", ""},          // not a path segment
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Dx&limit=abc", "list", ""}, // options do not decode
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Dx&timeoutSeconds=1.5", "list", ""},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Dx&limit=%2B1", "list", "x"},        // ParseInt takes "+1"
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3Dz,metadata.name%3Da", "list", "a"}, // sorted
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name%3D", "list", ""},
		{http.MethodGet, "/api/v1/secrets?fieldSelector=metadata.name!%3Dz,metadata.name%3Dy", "list", "y"},
		{http.MethodGet, "/api/v1/secrets?watch=", "watch", ""},
		{http.MethodGet, "/api/v1/secrets?watch=FALSE", "list", ""},
	} {
		got, err := parseURL(t, test.method, test.url)
		if err != nil || got.Verb != test.verb || got.Name != test.name {
			t.Errorf("%s %s: verb %q name %q, %v; want %q %q", test.method, test.url, got.Verb, got.Name, err,
				test.verb, test.name)
		}
	}
}
