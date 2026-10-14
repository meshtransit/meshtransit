package dataplane

import "golang.zx2c4.com/wireguard/conn"

// On Android the app's VPN protects the packet path's sockets, so the
// default bind must show them (protectBindSockets).
var _ conn.PeekLookAtSocketFd = (*conn.StdNetBind)(nil)
