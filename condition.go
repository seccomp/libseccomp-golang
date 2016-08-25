package seccomp

import(
	"fmt"
)

// ScmpCondition represents a rule in a libseccomp filter context
type ScmpCondition struct {
	Argument uint          `json:"argument,omitempty"`
	Op       ScmpCompareOp `json:"operator,omitempty"`
	Operand1 uint64        `json:"operand_one,omitempty"`
	Operand2 uint64        `json:"operand_two,omitempty"`
}

// MakeCondition creates and returns a new condition to attach to a filter rule.
// Associated rules will only match if this condition is true.
// Accepts the number the argument we are checking, and a comparison operator
// and value to compare to.
// The rule will match if argument $arg (zero-indexed) of the syscall is
// $COMPARE_OP the provided comparison value.
// Some comparison operators accept two values. Masked equals, for example,
// will mask $arg of the syscall with the second value provided (via bitwise
// AND) and then compare against the first value provided.
// For example, in the less than or equal case, if the syscall argument was
// 0 and the value provided was 1, the condition would match, as 0 is less
// than or equal to 1.
// Return either an error on bad argument or a valid ScmpCondition struct.
func MakeCondition(arg uint, comparison ScmpCompareOp, values ...uint64) (ScmpCondition, error) {
	var condStruct ScmpCondition

	if comparison == CompareInvalid {
		return condStruct, fmt.Errorf("invalid comparison operator")
	} else if arg > 5 {
		return condStruct, fmt.Errorf("syscalls only have up to 6 arguments")
	} else if len(values) > 2 {
		return condStruct, fmt.Errorf("conditions can have at most 2 arguments")
	} else if len(values) == 0 {
		return condStruct, fmt.Errorf("must provide at least one value to compare against")
	}

	condStruct.Argument = arg
	condStruct.Op = comparison
	condStruct.Operand1 = values[0]
	if len(values) == 2 {
		condStruct.Operand2 = values[1]
	} else {
		condStruct.Operand2 = 0 // Unused
	}

	return condStruct, nil
}
