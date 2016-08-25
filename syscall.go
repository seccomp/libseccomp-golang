package seccomp

import(
	"fmt"
	"unsafe"
)

// #cgo pkg-config: libseccomp
// #include <stdlib.h>
// #include <seccomp.h>
import "C"

// ScmpSyscall represents a Linux System Call
type ScmpSyscall int32

// GetName retrieves the name of a syscall from its number.
// Acts on any syscall number.
// Returns either a string containing the name of the syscall, or an error.
func (s ScmpSyscall) GetName() (string, error) {
	return s.GetNameByArch(ArchNative)
}

// GetNameByArch retrieves the name of a syscall from its number for a given
// architecture.
// Acts on any syscall number.
// Accepts a valid architecture constant.
// Returns either a string containing the name of the syscall, or an error.
// if the syscall is unrecognized or an issue occurred.
func (s ScmpSyscall) GetNameByArch(arch ScmpArch) (string, error) {
	if err := sanitizeArch(arch); err != nil {
		return "", err
	}

	cString := C.seccomp_syscall_resolve_num_arch(arch.toNative(), C.int(s))
	if cString == nil {
		return "", fmt.Errorf("could not resolve syscall name")
	}
	defer C.free(unsafe.Pointer(cString))

	finalStr := C.GoString(cString)
	return finalStr, nil
}
