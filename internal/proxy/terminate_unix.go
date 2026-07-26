//go:build !windows

package proxy

import (
	"os"
	"syscall"
)

// terminate asks the server to shut down cleanly.
func terminate(p *os.Process) { _ = p.Signal(syscall.SIGTERM) }
