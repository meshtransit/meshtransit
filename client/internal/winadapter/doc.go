// Package winadapter names the MeshTransit Wintun adapter on Windows. The
// data plane creates it, and host network watching, gateway lookup, DNS and
// firewall setup recognise it by its fixed GUID, not by its name, which an
// administrator can change in Network Connections.
package winadapter

// Name is the adapter's name in Network Connections when it is created.
const Name = "MeshTransit"
