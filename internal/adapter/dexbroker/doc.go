// Package dexbroker owns the only boundary where MeshCore may depend on Dex
// runtime packages.
//
// Dex configuration, storage, connector, and token types must remain private to
// this package. The rest of MeshCore communicates through product-owned
// contracts so a qualified Dex upgrade cannot leak into domain or application
// code. Its lifecycle shell fences admission and joins a version-specific
// component without owning a network listener.
package dexbroker
