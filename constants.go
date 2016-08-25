package seccomp

const (
	// Valid architectures recognized by libseccomp
	// ARM64 and all MIPS architectures are unsupported by versions of the
	// library before v2.2 and will return errors if used

	// ArchInvalid is a placeholder to ensure uninitialized ScmpArch
	// variables are invalid
	ArchInvalid ScmpArch = iota
	// ArchNative is the native architecture of the kernel
	ArchNative ScmpArch = iota
	// ArchX86 represents 32-bit x86 syscalls
	ArchX86 ScmpArch = iota
	// ArchAMD64 represents 64-bit x86-64 syscalls
	ArchAMD64 ScmpArch = iota
	// ArchX32 represents 64-bit x86-64 syscalls (32-bit pointers)
	ArchX32 ScmpArch = iota
	// ArchARM represents 32-bit ARM syscalls
	ArchARM ScmpArch = iota
	// ArchARM64 represents 64-bit ARM syscalls
	ArchARM64 ScmpArch = iota
	// ArchMIPS represents 32-bit MIPS syscalls
	ArchMIPS ScmpArch = iota
	// ArchMIPS64 represents 64-bit MIPS syscalls
	ArchMIPS64 ScmpArch = iota
	// ArchMIPS64N32 represents 64-bit MIPS syscalls (32-bit pointers)
	ArchMIPS64N32 ScmpArch = iota
	// ArchMIPSEL represents 32-bit MIPS syscalls (little endian)
	ArchMIPSEL ScmpArch = iota
	// ArchMIPSEL64 represents 64-bit MIPS syscalls (little endian)
	ArchMIPSEL64 ScmpArch = iota
	// ArchMIPSEL64N32 represents 64-bit MIPS syscalls (little endian,
	// 32-bit pointers)
	ArchMIPSEL64N32 ScmpArch = iota
	// ArchPPC represents 32-bit POWERPC syscalls
	ArchPPC ScmpArch = iota
	// ArchPPC64 represents 64-bit POWER syscalls (big endian)
	ArchPPC64 ScmpArch = iota
	// ArchPPC64LE represents 64-bit POWER syscalls (little endian)
	ArchPPC64LE ScmpArch = iota
	// ArchS390 represents 31-bit System z/390 syscalls
	ArchS390 ScmpArch = iota
	// ArchS390X represents 64-bit System z/390 syscalls
	ArchS390X ScmpArch = iota
)

const (
	// Supported actions on filter match

	// ActInvalid is a placeholder to ensure uninitialized ScmpAction
	// variables are invalid
	ActInvalid ScmpAction = iota
	// ActKill kills the process
	ActKill ScmpAction = iota
	// ActTrap throws SIGSYS
	ActTrap ScmpAction = iota
	// ActErrno causes the syscall to return a negative error code. This
	// code can be set with the SetReturnCode method
	ActErrno ScmpAction = iota
	// ActTrace causes the syscall to notify tracing processes with the
	// given error code. This code can be set with the SetReturnCode method
	ActTrace ScmpAction = iota
	// ActAllow permits the syscall to continue execution
	ActAllow ScmpAction = iota
)

const (
	// These are comparison operators used in conditional seccomp rules
	// They are used to compare the value of a single argument of a syscall
	// against a user-defined constant

	// CompareInvalid is a placeholder to ensure uninitialized ScmpCompareOp
	// variables are invalid
	CompareInvalid ScmpCompareOp = iota
	// CompareNotEqual returns true if the argument is not equal to the
	// given value
	CompareNotEqual ScmpCompareOp = iota
	// CompareLess returns true if the argument is less than the given value
	CompareLess ScmpCompareOp = iota
	// CompareLessOrEqual returns true if the argument is less than or equal
	// to the given value
	CompareLessOrEqual ScmpCompareOp = iota
	// CompareEqual returns true if the argument is equal to the given value
	CompareEqual ScmpCompareOp = iota
	// CompareGreaterEqual returns true if the argument is greater than or
	// equal to the given value
	CompareGreaterEqual ScmpCompareOp = iota
	// CompareGreater returns true if the argument is greater than the given
	// value
	CompareGreater ScmpCompareOp = iota
	// CompareMaskedEqual returns true if the argument is equal to the given
	// value, when masked (bitwise &) against the second given value
	CompareMaskedEqual ScmpCompareOp = iota
)
