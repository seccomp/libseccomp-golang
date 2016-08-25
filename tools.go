package seccomp

import(
	"fmt"
	"strings"
	"unsafe"
)

// #cgo pkg-config: libseccomp
// #include <stdlib.h>
// #include <seccomp.h>
import "C"

// GetLibraryVersion returns the version of the library the bindings are built
// against.
// The version is formatted as follows: Major.Minor.Micro
func GetLibraryVersion() (major, minor, micro int) {
	return verMajor, verMinor, verMicro
}

// GetNativeArch returns architecture token representing the native kernel
// architecture
func GetNativeArch() (ScmpArch, error) {
	arch := C.seccomp_arch_native()

	return archFromNative(arch)
}

// GetSyscallFromName returns the number of a syscall by name on the kernel's
// native architecture.
// Accepts a string containing the name of a syscall.
// Returns the number of the syscall, or an error if no syscall with that name
// was found.
func GetSyscallFromName(name string) (ScmpSyscall, error) {
	cString := C.CString(name)
	defer C.free(unsafe.Pointer(cString))

	result := C.seccomp_syscall_resolve_name(cString)
	if result == scmpError {
		return 0, fmt.Errorf("could not resolve name to syscall")
	}

	return ScmpSyscall(result), nil
}

// GetSyscallFromNameByArch returns the number of a syscall by name for a given
// architecture's ABI.
// Accepts the name of a syscall and an architecture constant.
// Returns the number of the syscall, or an error if an invalid architecture is
// passed or a syscall with that name was not found.
func GetSyscallFromNameByArch(name string, arch ScmpArch) (ScmpSyscall, error) {
	if err := sanitizeArch(arch); err != nil {
		return 0, err
	}

	cString := C.CString(name)
	defer C.free(unsafe.Pointer(cString))

	result := C.seccomp_syscall_resolve_name_arch(arch.toNative(), cString)
	if result == scmpError {
		return 0, fmt.Errorf("could not resolve name to syscall")
	}

	return ScmpSyscall(result), nil
}

// GetArchFromString returns an ScmpArch constant from a string representing an
// architecture
func GetArchFromString(arch string) (ScmpArch, error) {
	switch strings.ToLower(arch) {
	case "x86":
		return ArchX86, nil
	case "amd64", "x86-64", "x86_64", "x64":
		return ArchAMD64, nil
	case "x32":
		return ArchX32, nil
	case "arm":
		return ArchARM, nil
	case "arm64", "aarch64":
		return ArchARM64, nil
	case "mips":
		return ArchMIPS, nil
	case "mips64":
		return ArchMIPS64, nil
	case "mips64n32":
		return ArchMIPS64N32, nil
	case "mipsel":
		return ArchMIPSEL, nil
	case "mipsel64":
		return ArchMIPSEL64, nil
	case "mipsel64n32":
		return ArchMIPSEL64N32, nil
	case "ppc":
		return ArchPPC, nil
	case "ppc64":
		return ArchPPC64, nil
	case "ppc64le":
		return ArchPPC64LE, nil
	case "s390":
		return ArchS390, nil
	case "s390x":
		return ArchS390X, nil
	default:
		return ArchInvalid, fmt.Errorf("cannot convert unrecognized string %s", arch)
	}
}

// GetStringFromArch returns a string representation of an architecture
func GetStringFromArch(arch ScmpArch) string {
	switch arch {
	case ArchX86:
		return "x86"
	case ArchAMD64:
		return "amd64"
	case ArchX32:
		return "x32"
	case ArchARM:
		return "arm"
	case ArchARM64:
		return "arm64"
	case ArchMIPS:
		return "mips"
	case ArchMIPS64:
		return "mips64"
	case ArchMIPS64N32:
		return "mips64n32"
	case ArchMIPSEL:
		return "mipsel"
	case ArchMIPSEL64:
		return "mipsel64"
	case ArchMIPSEL64N32:
		return "mipsel64n32"
	case ArchPPC:
		return "ppc"
	case ArchPPC64:
		return "ppc64"
	case ArchPPC64LE:
		return "ppc64le"
	case ArchS390:
		return "s390"
	case ArchS390X:
		return "s390x"
	case ArchNative:
		return "native"
	case ArchInvalid:
		return "Invalid architecture"
	default:
		return "Unknown architecture"
	}
}

// GetStringFromCompareOp returns a string representation of a comparison operator constant
func GetStringFromCompareOp(compareOp ScmpCompareOp) string {
	switch compareOp {
	case CompareNotEqual:
		return "Not equal"
	case CompareLess:
		return "Less than"
	case CompareLessOrEqual:
		return "Less than or equal to"
	case CompareEqual:
		return "Equal"
	case CompareGreaterEqual:
		return "Greater than or equal to"
	case CompareGreater:
		return "Greater than"
	case CompareMaskedEqual:
		return "Masked equality"
	case CompareInvalid:
		return "Invalid comparison operator"
	default:
		return "Unrecognized comparison operator"
	}
}
