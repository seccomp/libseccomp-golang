package seccomp

// ScmpCompareOp represents a comparison operator which can be used in a filter
// rule
type ScmpCompareOp uint

// String returns a string representation of a comparison operator constant
func (a ScmpCompareOp) String() string {
	return GetStringFromCompareOp(a)
}
