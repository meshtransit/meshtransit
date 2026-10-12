//go:build windows

package main

// ownInterfaces is empty on Windows: netwatch recognises the Wintun adapter
// by its fixed GUID, since an administrator can rename it.
var ownInterfaces []string
