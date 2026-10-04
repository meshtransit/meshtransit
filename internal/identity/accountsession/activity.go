package accountsession

import "context"

type activityContextKey struct{}

// WithActivity marks a verified, same-origin Console activity probe. Only the
// browser management boundary should set it after validating the request.
func WithActivity(ctx context.Context) context.Context {
	return context.WithValue(ctx, activityContextKey{}, true)
}

// IsActivity distinguishes an explicit Console probe from ordinary reads.
func IsActivity(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, ok := ctx.Value(activityContextKey{}).(bool)
	return ok && value
}
