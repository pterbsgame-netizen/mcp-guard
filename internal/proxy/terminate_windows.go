//go:build windows

package proxy

import "os"

// terminate on Windows is the same thing as killing.
//
// There is no SIGTERM: os.Process.Signal accepts only os.Kill here and returns
// "not supported by windows" for anything else. A genuinely graceful stop needs
// either GenerateConsoleCtrlEvent (which requires sharing a console with the
// child and hits the whole process group) or a job object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Both are out of scope for stage 0.
//
// Practical consequence: closing the server's stdin is the only polite shutdown
// signal we have on Windows, and the reap ladder collapses from three rungs to
// two. Worth remembering before writing tests that assert on graceful exits.
func terminate(p *os.Process) { _ = p.Kill() }
