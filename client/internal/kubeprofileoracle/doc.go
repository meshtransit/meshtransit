// Package kubeprofileoracle holds the differential test of Kubernetes
// access profiles (K2b, K2 design §14): each sample profile becomes real RBAC
// for an oracle ServiceAccount of a lab cluster, and for every request of a
// corpus the decision of shared/kubeprofile, on what kubereq reads of the
// request, must equal the API server's own for that account, but for the
// cases the design makes stricter on purpose (S1–S7). It has no code outside
// its tests.
package kubeprofileoracle
