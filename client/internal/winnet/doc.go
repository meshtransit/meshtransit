// Package winnet configures the MeshTransit Wintun adapter on Windows:
// addresses, per-peer routes and MTU, through the IP Helper API (the
// winipcfg package of the WireGuard project). meshd's service does this
// itself, because a Wintun session cannot be handed to another process.
package winnet
