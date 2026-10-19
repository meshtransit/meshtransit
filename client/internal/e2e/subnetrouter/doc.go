// Package subnetrouter is the end-to-end test of subnet routing on a real
// kernel: a consumer reaches a host in a Site through a router, over
// WireGuard between network namespaces, and moves to another router when the
// first one dies. Each node runs the real helper (netadmin server) and data
// plane in a namespace of its own, with a network map the test builds, so
// no Core is needed.
//
// It needs Linux, root, iproute2 and nftables, and builds only with the e2e
// tag:
//
//	go test -c -tags e2e -o subnetrouter.test ./internal/e2e/subnetrouter
//	sudo ./subnetrouter.test -test.v
//
// MESHTRANSIT_E2E_BENCH=path also measures throughput and latency through the
// router and writes them to path as JSON.
package subnetrouter
