// Tests for public API of libseccomp Go bindings

package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// execInSubprocess calls the go test binary again for the same test.
// This must be only top-level statement in the test function. Do not nest this.
// It will slightly defect the test log output as the test is entered twice
func execInSubprocess(t *testing.T, f func(t *testing.T)) {
	const subprocessEnvKey = `GO_SUBPROCESS_KEY`
	if testIDString, ok := os.LookupEnv(subprocessEnvKey); ok && testIDString == "1" {
		t.Run(`subprocess`, f)
		return
	}

	cmd := exec.Command(os.Args[0])
	cmd.Args = []string{os.Args[0], "-test.run=" + t.Name() + "$", "-test.v=true"}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, `-test.testlogfile=`) {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(),
		subprocessEnvKey+"=1",
	)
	cmd.Stdin = os.Stdin

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExpectedSeccompVersion(t *testing.T) {
	execInSubprocess(t, subprocessExpectedSeccompVersion)
}

func subprocessExpectedSeccompVersion(t *testing.T) {
	// This environment variable can be set by CI.
	const name = "_EXPECTED_LIBSECCOMP_VERSION"

	expVer := os.Getenv(name)
	if expVer == "" {
		t.Skip(name, "not set")
	}
	expVer = strings.TrimPrefix(expVer, "v")

	curVer := fmt.Sprintf("%d.%d.%d", verMajor, verMinor, verMicro)
	t.Logf("testing against libseccomp %s", curVer)
	if curVer != expVer {
		t.Fatalf("libseccomp version mismatch: must be %s, got %s", expVer, curVer)
	}
}

// Type Function Tests

func APILevelIsSupported() bool {
	return verMajor > 2 ||
		(verMajor == 2 && verMinor >= 4)
}

func TestGetAPILevel(t *testing.T) {
	execInSubprocess(t, subprocessGetAPILevel)
}

func subprocessGetAPILevel(t *testing.T) {
	api, err := GetAPI()
	if !APILevelIsSupported() {
		if api != 0 {
			t.Errorf("API level returned despite lack of support: %v", api)
		} else if err == nil {
			t.Errorf("No error returned despite lack of API level support")
		}

		t.Skipf("Skipping test: %s", err)
	} else if err != nil {
		t.Errorf("Error getting API level: %s", err)
	}
	t.Logf("Got API level of %v\n", api)
}

func TestSetAPILevel(t *testing.T) {
	execInSubprocess(t, subprocessSetAPILevel)
}

func subprocessSetAPILevel(t *testing.T) {
	const expectedAPI = uint(1)

	err := SetAPI(expectedAPI)
	if !APILevelIsSupported() {
		if err == nil {
			t.Errorf("No error returned despite lack of API level support")
		}

		t.Skipf("Skipping test: %s", err)
	} else if err != nil {
		t.Errorf("Error setting API level: %s", err)
	}

	api, err := GetAPI()
	if err != nil {
		t.Errorf("Error getting API level: %s", err)
	} else if api != expectedAPI {
		t.Errorf("Got API level %v: expected %v", api, expectedAPI)
	}
}

func TestActionSetReturnCode(t *testing.T) {
	if ActInvalid.SetReturnCode(0x0010) != ActInvalid {
		t.Errorf("Able to set a return code on invalid action!")
	}

	codeSet := ActErrno.SetReturnCode(0x0001)
	if codeSet == ActErrno || codeSet.GetReturnCode() != 0x0001 {
		t.Errorf("Could not set return code on ActErrno")
	}
}

func TestSyscallGetName(t *testing.T) {
	call1 := ScmpSyscall(0x1)
	callFail := ScmpSyscall(0x999)

	name, err := call1.GetName()
	if err != nil {
		t.Errorf("Error getting syscall name for number 0x1")
	} else if len(name) == 0 {
		t.Errorf("Empty name returned for syscall 0x1")
	}
	t.Logf("Got name of syscall 0x1 on native arch as %s\n", name)

	_, err = callFail.GetName()
	if err == nil {
		t.Errorf("Getting nonexistent syscall should error!")
	}
}

func TestSyscallGetNameByArch(t *testing.T) {
	call1 := ScmpSyscall(0x1)
	callInvalid := ScmpSyscall(0x999)
	archGood := ArchAMD64
	archBad := ArchInvalid

	name, err := call1.GetNameByArch(archGood)
	if err != nil {
		t.Errorf("Error getting syscall name for number 0x1 and arch AMD64")
	} else if name != "write" {
		t.Errorf("Got incorrect name for syscall 0x1 - expected write, got %s", name)
	}

	_, err = call1.GetNameByArch(archBad)
	if err == nil {
		t.Errorf("Bad architecture GetNameByArch() should error!")
	}

	_, err = callInvalid.GetNameByArch(archGood)
	if err == nil {
		t.Errorf("Bad syscall GetNameByArch() should error!")
	}

	_, err = callInvalid.GetNameByArch(archBad)
	if err == nil {
		t.Errorf("Bad syscall and bad arch GetNameByArch() should error!")
	}
}

func TestGetSyscallFromName(t *testing.T) {
	name1 := "write"
	nameInval := "NOTASYSCALL"

	syscall, err := GetSyscallFromName(name1)
	if err != nil {
		t.Errorf("Error getting syscall number of write: %s", err)
	}
	t.Logf("Got syscall number of write on native arch as %d\n", syscall)

	_, err = GetSyscallFromName(nameInval)
	if err == nil {
		t.Errorf("Getting an invalid syscall should error!")
	}
}

func TestGetSyscallFromNameByArch(t *testing.T) {
	name1 := "write"
	nameInval := "NOTASYSCALL"
	arch1 := ArchAMD64
	archInval := ArchInvalid

	syscall, err := GetSyscallFromNameByArch(name1, arch1)
	if err != nil {
		t.Errorf("Error getting syscall number of write on AMD64: %s", err)
	}
	t.Logf("Got syscall number of write on AMD64 as %d\n", syscall)

	_, err = GetSyscallFromNameByArch(nameInval, arch1)
	if err == nil {
		t.Errorf("Getting invalid syscall with valid arch should error")
	}

	_, err = GetSyscallFromNameByArch(name1, archInval)
	if err == nil {
		t.Errorf("Getting valid syscall for invalid arch should error")
	}

	_, err = GetSyscallFromNameByArch(nameInval, archInval)
	if err == nil {
		t.Errorf("Getting invalid syscall for invalid arch should error")
	}
}

func TestMakeCondition(t *testing.T) {
	condition, err := MakeCondition(3, CompareNotEqual, 0x10)
	if err != nil {
		t.Errorf("Error making condition struct: %s", err)
	} else if condition.Argument != 3 || condition.Operand1 != 0x10 ||
		condition.Operand2 != 0 || condition.Op != CompareNotEqual {
		t.Errorf("Condition struct was filled incorrectly")
	}

	condition, err = MakeCondition(3, CompareMaskedEqual, 0x10, 0x20)
	if err != nil {
		t.Errorf("Error making condition struct: %s", err)
	} else if condition.Argument != 3 || condition.Operand1 != 0x10 ||
		condition.Operand2 != 0x20 || condition.Op != CompareMaskedEqual {
		t.Errorf("Condition struct was filled incorrectly")
	}

	_, err = MakeCondition(7, CompareNotEqual, 0x10)
	if err == nil {
		t.Errorf("Condition struct with bad syscall argument number should error")
	}

	_, err = MakeCondition(3, CompareInvalid, 0x10)
	if err == nil {
		t.Errorf("Condition struct with bad comparison operator should error")
	}

	_, err = MakeCondition(3, CompareMaskedEqual, 0x10, 0x20, 0x30)
	if err == nil {
		t.Errorf("MakeCondition with more than 2 arguments should fail")
	}

	_, err = MakeCondition(3, CompareMaskedEqual)
	if err == nil {
		t.Errorf("MakeCondition with no arguments should fail")
	}
}

// Utility Function Tests

func TestGetNativeArch(t *testing.T) {
	arch, err := GetNativeArch()
	if err != nil {
		t.Errorf("GetNativeArch should not error!")
	}
	t.Logf("Got native arch of system as %s\n", arch.String())
}

// Filter Tests

func TestFilterCreateRelease(t *testing.T) {
	_, err := NewFilter(ActInvalid)
	if err == nil {
		t.Errorf("Can create filter with invalid action")
	}

	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}

	if !filter.IsValid() {
		t.Errorf("Filter created by NewFilter was not valid")
	}

	filter.Release()

	if filter.IsValid() {
		t.Errorf("Filter is valid after being released")
	}
}

func TestFilterReset(t *testing.T) {
	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	// Ensure the default action is ActKill
	action, err := filter.GetDefaultAction()
	if err != nil {
		t.Errorf("Error getting default action of filter")
	} else if action != ActKillThread {
		t.Errorf("Default action of filter was set incorrectly!")
	}

	// Reset with a different default action
	err = filter.Reset(ActAllow)
	if err != nil {
		t.Errorf("Error resetting filter!")
	}

	valid := filter.IsValid()
	if !valid {
		t.Errorf("Filter is no longer valid after reset!")
	}

	// The default action should no longer be ActKill
	action, err = filter.GetDefaultAction()
	if err != nil {
		t.Errorf("Error getting default action of filter")
	} else if action != ActAllow {
		t.Errorf("Default action of filter was set incorrectly!")
	}
}

func TestFilterArchFunctions(t *testing.T) {
	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	arch, err := GetNativeArch()
	if err != nil {
		t.Errorf("Error getting native architecture: %s", err)
	}

	present, err := filter.IsArchPresent(arch)
	if err != nil {
		t.Errorf("Error retrieving arch from filter: %s", err)
	} else if !present {
		t.Errorf("Filter does not contain native architecture by default")
	}

	// Adding the native arch again should succeed, as it's already present
	err = filter.AddArch(arch)
	if err != nil {
		t.Errorf("Adding arch to filter already containing it should succeed")
	}

	// Make sure we don't add the native arch again
	prospectiveArch := ArchX86
	if arch == ArchX86 {
		prospectiveArch = ArchAMD64
	}

	// Check to make sure this other arch isn't in the filter
	present, err = filter.IsArchPresent(prospectiveArch)
	if err != nil {
		t.Errorf("Error retrieving arch from filter: %s", err)
	} else if present {
		t.Errorf("Arch not added to filter is present")
	}

	// Try removing the nonexistent arch - should succeed
	err = filter.RemoveArch(prospectiveArch)
	if err != nil {
		t.Errorf("Error removing nonexistent arch: %s", err)
	}

	// Add an arch, see if it's in the filter
	err = filter.AddArch(prospectiveArch)
	if err != nil {
		t.Errorf("Could not add arch %s to filter: %s",
			prospectiveArch.String(), err)
	}

	present, err = filter.IsArchPresent(prospectiveArch)
	if err != nil {
		t.Errorf("Error retrieving arch from filter: %s", err)
	} else if !present {
		t.Errorf("Filter does not contain architecture %s after it was added",
			prospectiveArch.String())
	}

	// Remove the arch again, make sure it's not in the filter
	err = filter.RemoveArch(prospectiveArch)
	if err != nil {
		t.Errorf("Could not remove arch %s from filter: %s",
			prospectiveArch.String(), err)
	}

	present, err = filter.IsArchPresent(prospectiveArch)
	if err != nil {
		t.Errorf("Error retrieving arch from filter: %s", err)
	} else if present {
		t.Errorf("Filter contains architecture %s after it was removed",
			prospectiveArch.String())
	}
}

func TestFilterAttributeGettersAndSetters(t *testing.T) {
	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	act, err := filter.GetDefaultAction()
	if err != nil {
		t.Errorf("Error getting default action: %s", err)
	} else if act != ActKillThread {
		t.Errorf("Default action was set incorrectly")
	}

	err = filter.SetBadArchAction(ActAllow)
	if err != nil {
		t.Errorf("Error setting bad arch action: %s", err)
	}

	act, err = filter.GetBadArchAction()
	if err != nil {
		t.Errorf("Error getting bad arch action")
	} else if act != ActAllow {
		t.Errorf("Bad arch action was not set correctly!")
	}

	err = filter.SetBadArchAction(ActInvalid)
	if err == nil {
		t.Errorf("Setting bad arch action to an invalid action should error")
	}

	err = filter.SetNoNewPrivsBit(false)
	if err != nil {
		t.Errorf("Error setting no new privileges bit")
	}

	privs, err := filter.GetNoNewPrivsBit()
	if err != nil {
		t.Errorf("Error getting no new privileges bit!")
	} else if privs != false {
		t.Errorf("No new privileges bit was not set correctly")
	}

	// Checks that require API level >= 3 and libseccomp >= 2.4.0.
	if err := checkAPI(t.Name(), 3, 2, 4, 0); err != nil {
		t.Logf("Skipping the rest of the test: %v", err)
		return
	}

	err = filter.SetLogBit(true)
	if err != nil {
		t.Errorf("Error setting log bit: %v", err)
	}

	log, err := filter.GetLogBit()
	if err != nil {
		t.Errorf("Error getting log bit: %v", err)
	} else if log != true {
		t.Error("Log bit was not set correctly")
	}

	// Checks that require API level >= 4 and libseccomp >= 2.5.0.
	if err := checkAPI(t.Name(), 4, 2, 5, 0); err != nil {
		t.Logf("Skipping the rest of the test: %v", err)
		return
	}

	err = filter.SetSSB(true)
	if err != nil {
		t.Errorf("Error setting SSB bit: %v", err)
	}

	ssb, err := filter.GetSSB()
	if err != nil {
		t.Errorf("Error getting SSB bit: %v", err)
	} else if ssb != true {
		t.Error("SSB bit was not set correctly")
	}

	err = filter.SetOptimize(2)
	if err != nil {
		t.Errorf("Error setting optimize level: %v", err)
	}

	level, err := filter.GetOptimize()
	if err != nil {
		t.Errorf("Error getting optimize level: %v", err)
	} else if level != 2 {
		t.Error("Optimize level was not set correctly")
	}

	err = filter.SetRawRC(true)
	if err != nil {
		t.Errorf("Error setting RawRC flag: %v", err)
	}

	rawrc, err := filter.GetRawRC()
	if err != nil {
		t.Errorf("Error getting RawRC flag: %v", err)
	} else if rawrc != true {
		t.Error("RawRC flag was not set correctly")
	}
}

func TestMergeFilters(t *testing.T) {
	filter1, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}

	filter2, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}

	// Need to remove the native arch and add another to the second filter
	// Filters must NOT share architectures to be successfully merged
	nativeArch, err := GetNativeArch()
	if err != nil {
		t.Errorf("Error getting native arch: %s", err)
	}

	prospectiveArch := ArchAMD64
	if nativeArch == ArchAMD64 {
		prospectiveArch = ArchX86
	}

	err = filter2.AddArch(prospectiveArch)
	if err != nil {
		t.Errorf("Error adding architecture to filter: %s", err)
	}

	err = filter2.RemoveArch(nativeArch)
	if err != nil {
		t.Errorf("Error removing architecture from filter: %s", err)
	}

	err = filter1.Merge(filter2)
	if err != nil {
		t.Errorf("Error merging filters: %s", err)
	}

	if filter2.IsValid() {
		t.Errorf("Source filter should not be valid after merging")
	}

	filter3, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter3.Release()

	err = filter1.Merge(filter3)
	if err == nil {
		t.Errorf("Attributes should have to match to merge filters")
	}
}

func TestAddRuleErrors(t *testing.T) {
	execInSubprocess(t, subprocessAddRuleErrors)
}

func subprocessAddRuleErrors(t *testing.T) {
	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	err = filter.AddRule(ScmpSyscall(0x1), ActAllow)
	if err == nil {
		t.Error("expected error, got nil")
	} else if err != errDefAction {
		t.Errorf("expected error %v, got %v", errDefAction, err)
	}
}

func TestRuleAddAndLoad(t *testing.T) {
	execInSubprocess(t, subprocessRuleAddAndLoad)
}

func subprocessRuleAddAndLoad(t *testing.T) {
	// Test #1: Add a trivial filter
	filter1, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter1.Release()

	call, err := GetSyscallFromName("getpid")
	if err != nil {
		t.Errorf("Error getting syscall number of getpid: %s", err)
	}

	call2, err := GetSyscallFromName("setreuid")
	if err != nil {
		t.Errorf("Error getting syscall number of setreuid: %s", err)
	}

	call3, err := GetSyscallFromName("setreuid32")
	if err != nil {
		t.Errorf("Error getting syscall number of setreuid32: %s", err)
	}

	uid := syscall.Getuid()
	euid := syscall.Geteuid()

	err = filter1.AddRule(call, ActErrno.SetReturnCode(0x1))
	if err != nil {
		t.Errorf("Error adding rule to restrict syscall: %s", err)
	}

	cond, err := MakeCondition(1, CompareEqual, uint64(euid))
	if err != nil {
		t.Errorf("Error making rule to restrict syscall: %s", err)
	}

	cond2, err := MakeCondition(0, CompareEqual, uint64(uid))
	if err != nil {
		t.Errorf("Error making rule to restrict syscall: %s", err)
	}

	conditions := []ScmpCondition{cond, cond2}

	err = filter1.AddRuleConditional(call2, ActErrno.SetReturnCode(0x2), conditions)
	if err != nil {
		t.Errorf("Error adding conditional rule: %s", err)
	}

	err = filter1.AddRuleConditional(call3, ActErrno.SetReturnCode(0x3), conditions)
	if err != nil {
		t.Errorf("Error adding second conditional rule: %s", err)
	}

	err = filter1.Load()
	if err != nil {
		t.Errorf("Error loading filter: %s", err)
	}

	// Try making a simple syscall, it should error
	pid := syscall.Getpid()
	if pid != -1 {
		t.Errorf("Syscall should have returned error code!")
	}

	// Try making a Geteuid syscall that should normally succeed
	err = syscall.Setreuid(uid, euid)
	if err == nil {
		t.Errorf("Syscall should have returned error code!")
	} else if err != syscall.Errno(2) && err != syscall.Errno(3) {
		t.Errorf("Syscall returned incorrect error code - likely not blocked by Seccomp!")
	}
}

func TestLogAct(t *testing.T) {
	execInSubprocess(t, subprocessLogAct)
}

func subprocessLogAct(t *testing.T) {
	// ActLog requires API >=3 and libseccomp >= 2.4.0.
	if err := checkAPI(t.Name(), 3, 2, 4, 0); err != nil {
		t.Skip(err)
	}

	expectedPid := syscall.Getpid()

	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	call, err := GetSyscallFromName("getpid")
	if err != nil {
		t.Errorf("Error getting syscall number of getpid: %s", err)
	}

	err = filter.AddRule(call, ActLog)
	if err != nil {
		t.Errorf("Error adding rule to log syscall: %s", err)
	}

	err = filter.Load()
	if err != nil {
		t.Errorf("Error loading filter: %s", err)
	}

	// Try making a simple syscall, it should succeed
	pid := syscall.Getpid()
	if pid != expectedPid {
		t.Errorf("Syscall should have returned expected pid (%d != %d)", pid, expectedPid)
	}
}

func TestCreateActKillThreadFilter(t *testing.T) {
	execInSubprocess(t, subprocessCreateActKillThreadFilter)
}

func subprocessCreateActKillThreadFilter(t *testing.T) {
	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}

	if !filter.IsValid() {
		t.Errorf("Filter created by NewFilter was not valid")
	}
}

func TestCreateActKillProcessFilter(t *testing.T) {
	execInSubprocess(t, subprocessCreateActKillProcessFilter)
}

func subprocessCreateActKillProcessFilter(t *testing.T) {
	// Requires API level >= 3 and libseccomp >= 2.4.0
	if err := checkAPI(t.Name(), 3, 2, 4, 0); err != nil {
		t.Skip(err)
	}

	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}

	if !filter.IsValid() {
		t.Errorf("Filter created by NewFilter was not valid")
	}
}

//
// Seccomp notification tests
//

// notifTest describes a seccomp notification test
type notifTest struct {
	syscall     ScmpSyscall
	args        [6]uintptr
	arch        ScmpArch
	respErr     int32
	respVal     uint64
	respFlags   uint32
	expectedErr error
	expectedVal uint64
}

// notifHandler handles seccomp notifications and responses
func notifHandler(ch chan error, fd ScmpFd, tests []notifTest) {
	for _, test := range tests {
		req, err := NotifReceive(fd)
		if err != nil {
			ch <- fmt.Errorf("Error in NotifReceive(): %s", err)
			return
		}

		if req.Data.Syscall != test.syscall {
			want, _ := test.syscall.GetName()
			got, _ := req.Data.Syscall.GetName()
			ch <- fmt.Errorf("Error in notification request syscall: got %s, want %s", got, want)
			return
		}

		if req.Data.Arch != test.arch {
			ch <- fmt.Errorf("Error in notification request arch: got %s, want %s", req.Data.Arch, test.arch)
			return
		}

		for i, arg := range test.args {
			if arg != uintptr(req.Data.Args[i]) {
				ch <- fmt.Errorf("Error in syscall arg[%d]: got 0x%x, want 0x%x", i, req.Data.Args[i], arg)
				return
			}
		}

		// TOCTOU check
		if err := NotifIDValid(fd, req.ID); err != nil {
			ch <- fmt.Errorf("TOCTOU check failed: req.ID is no longer valid: %s", err)
			return
		}

		resp := &ScmpNotifResp{
			ID:    req.ID,
			Error: test.respErr,
			Val:   test.respVal,
			Flags: test.respFlags,
		}

		if err = NotifRespond(fd, resp); err != nil {
			ch <- fmt.Errorf("Error in notification response: %s", err)
			return
		}

		ch <- nil
	}
}

func TestNotif(t *testing.T) {
	execInSubprocess(t, subprocessNotif)
}

func subprocessNotif(t *testing.T) {
	if err := notifSupported(); err != nil {
		t.Skip(err)
	}

	arch, err := GetNativeArch()
	if err != nil {
		t.Errorf("Error in GetNativeArch(): %s", err)
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("Error in Getwd(): %s", err)
		return
	}

	// Create a filter that only notifies on chdir. This way, while the
	// seccomp filter applies to all threads, we can run the target and
	// handling in different go routines with no problem as only the target
	// goroutine uses chdir.
	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	call, err := GetSyscallFromName("chdir")
	if err != nil {
		t.Errorf("Error getting syscall number: %s", err)
	}

	err = filter.AddRule(call, ActNotify)
	if err != nil {
		t.Errorf("Error adding rule to log syscall: %s", err)
	}

	nonExistentPath, err := syscall.BytePtrFromString("/non-existent-path")
	if err != nil {
		t.Errorf("Error converting string: %s", err)
	}
	currentWorkingDirectory, err := syscall.BytePtrFromString(cwd)
	if err != nil {
		t.Errorf("Error converting string: %s", err)
	}

	tests := []notifTest{
		{
			syscall:     call,
			args:        [6]uintptr{uintptr(unsafe.Pointer(nonExistentPath)), 0, 0, 0, 0, 0},
			arch:        arch,
			respErr:     0,
			respVal:     0,
			respFlags:   NotifRespFlagContinue,
			expectedErr: syscall.ENOENT,
			expectedVal: ^uint64(0), // -1
		},
		{
			syscall:     call,
			args:        [6]uintptr{uintptr(unsafe.Pointer(currentWorkingDirectory)), 0, 0, 0, 0, 0},
			arch:        arch,
			respErr:     0,
			respVal:     0,
			respFlags:   NotifRespFlagContinue,
			expectedErr: syscall.Errno(0),
			expectedVal: 0,
		},
		{
			syscall:     call,
			args:        [6]uintptr{uintptr(unsafe.Pointer(nonExistentPath)), 0, 0, 0, 0, 0},
			arch:        arch,
			respErr:     int32(syscall.ENOMEDIUM),
			respVal:     ^uint64(0), // -1
			respFlags:   0,
			expectedErr: syscall.ENOMEDIUM,
			expectedVal: ^uint64(0), // -1
		},
		{
			syscall:     call,
			args:        [6]uintptr{uintptr(unsafe.Pointer(currentWorkingDirectory)), 0, 0, 0, 0, 0},
			arch:        arch,
			respErr:     int32(syscall.EPIPE),
			respVal:     ^uint64(0), // -1
			respFlags:   0,
			expectedErr: syscall.EPIPE,
			expectedVal: ^uint64(0), // -1
		},
	}

	seccompFdChan := make(chan ScmpFd)
	errorChan := make(chan error, 2)
	infoChan := make(chan string)
	done := make(chan struct{})

	go func() {
		err = filter.Load()
		if err != nil {
			t.Errorf("Error loading filter: %s", err)
		}

		fd, err := filter.GetNotifFd()
		if err != nil {
			t.Errorf("Error getting filter notification fd: %s", err)
		}

		if fd < 3 {
			t.Errorf("Error in notification fd: want >=3, got %v", fd)
		}
		seccompFdChan <- fd

		for i, test := range tests {
			infoChan <- fmt.Sprintf("Starting test %d", i)
			r1, r2, err := syscall.Syscall6(syscall.SYS_CHDIR,
				test.args[0], test.args[1], test.args[2], test.args[3], test.args[4], test.args[5])
			if err != test.expectedErr || uint64(r1) != test.expectedVal {
				errorChan <- fmt.Errorf("test #%d: error in syscall: want \"%s\", got \"%s\" (want %v, got r1=%v, r2=%v)",
					i, test.expectedErr, err, test.expectedVal, r1, r2)
			}
			infoChan <- fmt.Sprintf("Test %d completed", i)
		}
		done <- struct{}{}
	}()

	seccompFd := <-seccompFdChan
	go notifHandler(errorChan, seccompFd, tests)

L:
	for {
		select {
		case <-done:
			t.Logf("Tests completed")
			break L
		case msg := <-infoChan:
			t.Logf("%s", msg)
		case err = <-errorChan:
			if err != nil {
				t.Errorf("Received error: %s", err.Error())
				break L
			}
		case <-time.After(5 * time.Second):
			t.Errorf("Timeout during tests")
			break L
		}
	}
}

// TestNotifUnsupported is checking that the user notify API correctly returns
// an error when we don't have the proper api level, for example when linking
// with libseccomp < 2.5.0.
func TestNotifUnsupported(t *testing.T) {
	execInSubprocess(t, subprocessNotifUnsupported)
}

func subprocessNotifUnsupported(t *testing.T) {
	if err := notifSupported(); err == nil {
		t.Skip("seccomp notification is supported")
	}

	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Errorf("Error creating filter: %s", err)
	}
	defer filter.Release()

	_, err = filter.GetNotifFd()
	if err == nil {
		t.Error("GetNotifFd: got nil, want error")
	}
}
