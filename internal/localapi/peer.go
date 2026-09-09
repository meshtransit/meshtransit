package localapi

import (
	"context"
)

type peerIdentity struct {
	uid        uint32
	isPresent  bool
	isVerified bool
}

type peerContextKey struct{}

func contextWithPeer(ctx context.Context, peer peerIdentity) context.Context {
	return context.WithValue(ctx, peerContextKey{}, peer)
}

func peerFromContext(ctx context.Context) (peerIdentity, bool) {
	peer, ok := ctx.Value(peerContextKey{}).(peerIdentity)

	return peer, ok
}
