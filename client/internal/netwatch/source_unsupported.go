//go:build !linux && !darwin && !windows

package netwatch

import "time"

func newNativeSource(interval time.Duration) (changeSource, error) {
	return newPollingSource(interval), nil
}

func defaultRouteTokens(map[int]struct{}) ([]string, map[int]struct{}, error) {
	return []string{}, map[int]struct{}{}, nil
}
