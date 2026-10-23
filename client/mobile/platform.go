package mobile

// The interfaces below are implemented by the app (Kotlin on Android, Swift
// on iOS) and passed to NewEngine. gomobile binds them as platform
// interfaces, so every method takes and returns only types it can bind:
// strings, integers, booleans and byte slices.

// TunProvider gives the engine a configured TUN device.
//
// OpenTUN must configure the platform VPN interface with exactly the given
// addresses and routes (comma-separated CIDR prefixes), DNS servers
// (comma-separated addresses, often none), search domains (comma-separated
// names) and MTU, and return a
// fresh file descriptor the platform gives up: the engine owns it from then
// on and closes it. On Android that is ParcelFileDescriptor.detachFd() of
// VpnService.Builder.establish(); on iOS a dup() of the packet flow's utun
// descriptor. Returning a descriptor the platform still uses or closes later
// corrupts whichever file reuses that number. An error means no TUN; the
// engine stays offline and retries on its own schedule.
//
// matchDomains (comma-separated names) are the names iOS sends the DNS
// servers (NEDNSSettings.matchDomains); empty means every name. Android
// has no split DNS and ignores them: its DNS servers get every name.
type TunProvider interface {
	OpenTUN(addresses, routes, dns, searchDomains, matchDomains string, mtu int) (int, error)
}

// KeyStore holds the key that seals the Device's identity records on disk.
//
// EnvelopeKey returns the same 32 random bytes on every call for the
// lifetime of the installation: create them once and keep them in the
// Android Keystore or the iOS Keychain. Another key makes the stored
// identities unreadable, which the engine treats as a fresh install.
type KeyStore interface {
	EnvelopeKey() ([]byte, error)
}

// LogSink receives the engine's structured log, one JSON object per call.
// The lines carry no keys, tokens or packet contents. Log is called from one
// engine goroutine, never from the caller of an Engine method; records that
// arrive while Log is slow are dropped and counted in a later record.
type LogSink interface {
	Log(line string)
}

// SocketProtector excludes the engine's own sockets from the app's VPN.
//
// Android routes the whole app through its VpnService interface unless each
// socket is protected: Protect must call VpnService.protect(fd) and return
// its result. While no VPN interface is up there is nothing to exclude the
// socket from, and Protect returns true. iOS needs no protector: a packet
// tunnel's own traffic never enters the tunnel.
//
// Protect is called from many engine goroutines at once and must be safe
// for that; it runs before the socket is used, so it should return quickly.
//
// BindSocket binds the protected socket fd to the network named network,
// a handle the app gave SetHostResolvers (Android
// Network.fromNetworkHandle(network).bindSocket), so a network's DNS
// server is asked over that network. It returns false when it cannot; the
// socket then goes through the default network. iOS returns true.
type SocketProtector interface {
	Protect(fd int) bool
	BindSocket(fd int, network int64) bool
}
