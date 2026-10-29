//go:build !windows

package kubecafile

func retryableRename(error) bool { return false }
