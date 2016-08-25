package seccomp

import(
	"fmt"
)

// ScmpAction represents an action to be taken on a filter rule match in
// libseccomp
type ScmpAction uint

// String returns a string representation of a seccomp match action
func (a ScmpAction) String() string {
	switch a & 0xFFFF {
	case ActKill:
		return "Action: Kill Process"
	case ActTrap:
		return "Action: Send SIGSYS"
	case ActErrno:
		return fmt.Sprintf("Action: Return error code %d", (a >> 16))
	case ActTrace:
		return fmt.Sprintf("Action: Notify tracing processes with code %d",
			(a >> 16))
	case ActAllow:
		return "Action: Allow system call"
	default:
		return "Unrecognized Action"
	}
}

// SetReturnCode adds a return code to a supporting ScmpAction, clearing any
// existing code Only valid on ActErrno and ActTrace. Takes no action otherwise.
// Accepts 16-bit return code as argument.
// Returns a valid ScmpAction of the original type with the new error code set.
func (a ScmpAction) SetReturnCode(code int16) ScmpAction {
	aTmp := a & 0x0000FFFF
	if aTmp == ActErrno || aTmp == ActTrace {
		return (aTmp | (ScmpAction(code)&0xFFFF)<<16)
	}
	return a
}

// GetReturnCode returns the return code of an ScmpAction
func (a ScmpAction) GetReturnCode() int16 {
	return int16(a >> 16)
}
