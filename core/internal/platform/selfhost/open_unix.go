//go:build unix

package selfhost

import "syscall"

// openSafely: never through a final link, never blocking on a FIFO.
const openSafely = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
