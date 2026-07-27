//go:build !windows

package proxy

// secureFile is a no-op here: the log is created 0600 and the mode is honoured,
// which is exactly what the Windows implementation has to reconstruct by hand.
func secureFile(string) error { return nil }
