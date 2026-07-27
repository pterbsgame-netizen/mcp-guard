//go:build windows

package proxy

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// secureFile restricts path so that only the current user can read it.
//
// This exists because Go's 0600 is very nearly a no-op on Windows: the mode
// argument maps only to the read-only attribute, and the file otherwise
// inherits the parent directory's ACL. On a stock profile that means SYSTEM and
// the local Administrators group get full control of a file holding the verbatim
// contents of every tool result.
//
// The DACL written here is protected — inheritance is severed — with a single
// allow-all ACE for the owning user. An administrator can still take ownership,
// exactly as root can still read a 0600 file; the point is to stop the file
// from being readable by default.
func secureFile(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}

	// D:P     protected DACL, drop everything inherited from the directory
	// (A;;FA;;;SID)  allow, no inheritance, full access, to this user alone
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}

	// Applied by name rather than through SECURITY_ATTRIBUTES at create time,
	// because those only take effect for a file that does not exist yet, and
	// the log is normally reopened for append.
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("look up current user: %w", err)
	}
	return user.User.Sid, nil
}
