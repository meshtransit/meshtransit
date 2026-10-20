//go:build !darwin || ios

package dataplane

import "golang.zx2c4.com/wireguard/conn"

// interfaceBinder returns what binds the bind's sockets to an interface:
// the bind itself where wireguard-go offers it (Windows).
func interfaceBinder(inner conn.Bind, _ uint16) (conn.BindSocketToInterface, bool) {
	binder, ok := inner.(conn.BindSocketToInterface)
	return binder, ok
}
