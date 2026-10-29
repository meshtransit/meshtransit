package kubereq

import (
	"net/http"
	"net/url"
	"testing"
)

func classify(t *testing.T, method, raw string, header http.Header, options Options) Class {
	t.Helper()
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	class, _ := Classify(Request{Method: method, URL: target, Header: header}, options)
	return class
}

// Every type A request is recorded in Core first (K1 §5.7, K1b design §5);
// everything else is a read.
func TestClassify(t *testing.T) {
	t.Parallel()
	get, post := http.MethodGet, http.MethodPost
	upgrade := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}
	spdy := http.Header{"Connection": {"keep-alive, upgrade"}, "Upgrade": {"SPDY/3.1"}}
	for _, test := range []struct {
		method, url string
		header      http.Header
		want        Class
	}{
		// Reads.
		{get, "/api/v1/namespaces/default/pods", nil, ClassRead},
		{get, "/api/v1/namespaces/default/pods/web-0/log", nil, ClassRead},
		{get, "/api/v1/pods?watch=true", nil, ClassRead},
		{http.MethodHead, "/apis/apps/v1/deployments", nil, ClassRead},
		{get, "/api", nil, ClassRead},
		{get, "/api/v1", nil, ClassRead},
		{get, "/apis", nil, ClassRead},
		{get, "/apis/apps", nil, ClassRead},
		{get, "/apis/apps/v1", nil, ClassRead},
		{get, "/version", nil, ClassRead},
		{get, "/openapi/v2", nil, ClassRead},
		{get, "/openapi/v3/apis/apps/v1", nil, ClassRead},
		{get, "/.well-known/openid-configuration", nil, ClassRead},
		{get, "/openid/v1/jwks", nil, ClassRead},
		{get, "/readyz/etcd", nil, ClassRead},
		// Self-reviews only ask about the caller (Q65).
		{post, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", nil, ClassRead},
		{post, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", nil, ClassRead},
		{post, "/apis/authentication.k8s.io/v1/selfsubjectreviews", nil, ClassRead},
		{post, "/apis/authentication.k8s.io/v1beta1/selfsubjectreviews", nil, ClassRead},
		// Writes.
		{post, "/api/v1/namespaces/default/pods", nil, ClassWrite},
		{http.MethodPut, "/api/v1/namespaces/default/configmaps/a", nil, ClassWrite},
		{http.MethodPatch, "/apis/apps/v1/namespaces/default/deployments/a/scale", nil, ClassWrite},
		{http.MethodDelete, "/api/v1/namespaces/default/pods/a", nil, ClassWrite},
		{http.MethodDelete, "/api/v1/namespaces/default/pods", nil, ClassWrite},
		{post, "/api/v1/namespaces/default/pods/a/eviction", nil, ClassWrite},
		{post, "/api/v1/namespaces/default/pods/a/binding", nil, ClassWrite},
		{http.MethodPatch, "/api/v1/namespaces/default/pods/a/ephemeralcontainers", nil, ClassWrite},
		{post, "/api/v1/namespaces/default/serviceaccounts/a/token", nil, ClassWrite},
		{post, "/apis/authentication.k8s.io/v1/tokenreviews", nil, ClassWrite},
		{post, "/apis/authorization.k8s.io/v1/subjectaccessreviews", nil, ClassWrite},
		{post, "/apis/authorization.k8s.io/v1/namespaces/a/localsubjectaccessreviews", nil, ClassWrite},
		{post, "/api/v1/namespaces/default/secrets", nil, ClassWrite},
		// Interactive sessions, on any resource.
		{post, "/api/v1/namespaces/default/pods/a/exec?command=sh", nil, ClassExec},
		{get, "/api/v1/namespaces/default/pods/a/exec?command=sh", upgrade, ClassExec},
		{get, "/api/v1/namespaces/default/pods/a/attach", nil, ClassExec},
		{post, "/api/v1/namespaces/default/pods/a/portforward", spdy, ClassExec},
		{get, "/apis/subresources.kubevirt.io/v1/namespaces/a/virtualmachineinstances/vm/console", upgrade, ClassExec},
		{get, "/api/v1/namespaces/default/pods/a/log?follow=true", upgrade, ClassExec},
		// Proxies.
		{get, "/api/v1/namespaces/default/pods/a/proxy/metrics", nil, ClassProxy},
		{get, "/api/v1/namespaces/default/services/a:80/proxy/", nil, ClassProxy},
		{get, "/api/v1/nodes/n/proxy/stats", nil, ClassProxy},
		{get, "/api/v1/proxy/namespaces/default/pods/a", nil, ClassProxy},
		{get, "/apis/example.com/v1/widgets/a/proxy", nil, ClassProxy},
		// Secrets.
		{get, "/api/v1/namespaces/default/secrets/db", nil, ClassSecretRead},
		{get, "/api/v1/secrets", nil, ClassSecretRead},
		{get, "/api/v1/watch/namespaces/a/secrets", nil, ClassSecretRead},
		{get, "/api/v1/namespaces/a/secrets?watch=1&fieldSelector=metadata.name%3Ddb", nil, ClassSecretRead},
		{get, "/apis/bitnami.com/v1alpha1/namespaces/a/sealedsecrets", nil, ClassSecretRead},
		{get, "/apis/example.com/v1/secrets", nil, ClassRead}, // another group's "secrets"
		// A secret-like resource through a subresource (review b1 H1).
		{get, "/apis/bitnami.com/v1alpha1/namespaces/a/sealedsecrets/s/status", nil, ClassSecretRead},
		// A read is a GET or HEAD (review b1 M1).
		{post, "/api/v1/watch/namespaces/a/configmaps", nil, ClassUnparsed},
		{http.MethodDelete, "/apis/example.com/v1/watch/namespaces/a/things", nil, ClassUnparsed},
		{http.MethodPut, "/api/v1/watch/pods", nil, ClassUnparsed},
		// A self-review has no namespace, name or subresource (review b1 L1).
		{post, "/apis/authorization.k8s.io/v9/namespaces/a/selfsubjectaccessreviews/x", nil, ClassWrite},
		{post, "/apis/authorization.k8s.io/v1/namespaces/a/selfsubjectaccessreviews", nil, ClassWrite},
		// Upgrades however they are asked.
		{get, "/api/v1/namespaces/a/pods", http.Header{"Upgrade": {"websocket"}}, ClassExec},
		{get, "/api/v1/namespaces/a/pods", http.Header{"Connection": {"Upgrade"}}, ClassExec},
		{get, "/api/v1/namespaces/a/pods", http.Header{"Connection": {"x-UPGRADE"}}, ClassExec},
		{get, "/api/v1/namespaces/a/pods", http.Header{"Connection": {"keep-alive"}}, ClassRead},
		// What cannot be told apart.
		{get, "/api/v1/watch", nil, ClassUnparsed},
		{post, "/version", nil, ClassUnparsed},
		{get, "/metrics", nil, ClassUnparsed},
		{get, "/logs/kube-apiserver.log", nil, ClassUnparsed},
		{get, "/debug/pprof/", nil, ClassUnparsed},
		{post, "/apis/apps/v1", nil, ClassUnparsed},
		{"PROPFIND", "/api/v1/pods", nil, ClassUnparsed},
	} {
		got := classify(t, test.method, test.url, test.header,
			Options{SecretResources: []GroupResource{{Group: "bitnami.com", Resource: "sealedsecrets"}}})
		if got != test.want {
			t.Errorf("%s %s: %s, want %s", test.method, test.url, got, test.want)
		}
	}
}

// A privileged group's requests, and impersonation, are all type A, ahead
// of every other class.
func TestClassifyPrivileged(t *testing.T) {
	t.Parallel()
	for _, options := range []Options{{Privileged: true}, {Impersonating: true}} {
		for _, path := range []string{"/api/v1/pods", "/version", "/api/v1/namespaces/a/pods/b/exec"} {
			if got := classify(t, http.MethodGet, path, nil, options); got != ClassPrivileged {
				t.Errorf("%+v %s: %s", options, path, got)
			}
		}
	}
}

// Only reads are not type A.
func TestClassTypeA(t *testing.T) {
	t.Parallel()
	for _, class := range []Class{ClassWrite, ClassExec, ClassProxy, ClassSecretRead, ClassPrivileged, ClassUnparsed} {
		if !class.TypeA() {
			t.Errorf("%s is not type A", class)
		}
	}
	if ClassRead.TypeA() {
		t.Error("a read is type A")
	}
}
