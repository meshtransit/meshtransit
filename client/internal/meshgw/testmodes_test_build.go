//go:build meshgwtest

package meshgw

// testModes lets a build tagged meshgwtest run the enroll-only passthrough
// gateway and MESHGW_KUBE_API_BACKEND, for labs and tests (TD-SEC-69).
const testModes = true
