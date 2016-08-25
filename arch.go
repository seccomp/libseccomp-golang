package seccomp

// ScmpArch represents a CPU architecture. Seccomp can restrict syscalls on a
// per-architecture basis.
type ScmpArch uint

// String returns a string representation of an architecture constant
func (a ScmpArch) String() string {
	return GetStringFromArch(a)
}
