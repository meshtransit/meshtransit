package localapi

import (
	"context"
)

type peerIdentity struct {
	uid        uint32
	isPresent  bool
	isVerified bool
	// operator is set on Windows when the caller's token is LocalSystem or
	// an enabled member of Administrators or the operators group.
	operator bool
	// administrator is root on Unix, and LocalSystem or an elevated
	// Administrator on Windows.
	administrator bool
}

type peerContextKey struct{}

func contextWithPeer(ctx context.Context, peer peerIdentity) context.Context {
	return context.WithValue(ctx, peerContextKey{}, peer)
}

func peerFromContext(ctx context.Context) (peerIdentity, bool) {
	peer, ok := ctx.Value(peerContextKey{}).(peerIdentity)

	return peer, ok
}
