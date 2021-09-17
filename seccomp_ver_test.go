package seccomp

import (
	"testing"
)

func TestCheckVersion(t *testing.T) {
	for _, tc := range []struct {
		// input
		op      string
		x, y, z uint
		// expectations
		isErr bool
	}{
		{op: "verNew", x: 100, y: 99, z: 7, isErr: true},
		{op: "verMajor+1", x: verMajor + 1, isErr: true},
		{op: "verMinor+1", x: verMajor, y: verMinor + 1, isErr: true},
		{op: "verMicro+1", x: verMajor, y: verMinor, z: verMicro + 1, isErr: true},
		// Current version is guaranteed to succeed.
		{op: "verCur", x: verMajor, y: verMinor, z: verMicro},
		// 2.2.0 is guaranteed to succeed.
		{op: "verOld", x: 2, y: 2, z: 0},
	} {
		err := checkVersion(tc.op, tc.x, tc.y, tc.z)
		t.Log(err)
		if tc.isErr {
			if err == nil {
				t.Errorf("case %s: expected error, got nil", tc.op)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %s: expected no error, got %s", tc.op, err)
		}
	}
}

func TestCheckAPI(t *testing.T) {
	curAPI, _ := getAPI()
	for _, tc := range []struct {
		// input
		op      string
		level   uint
		x, y, z uint
		// expectations
		isErr bool
	}{
		{op: "apiHigh", level: 99, isErr: true},
		{op: "api+1", level: curAPI + 1, isErr: true},
		// Cases that should succeed.
		{op: "apiCur", level: curAPI},
		{op: "api0", level: 0},
		{op: "apiCur_verCur", level: curAPI, x: verMajor, y: verMinor, z: verMicro},
		// Adequate API level but version is too high.
		{op: "verHigh", level: 0, x: 99, isErr: true},
		// Other cases with version are checked by testCheckVersion.
	} {
		err := checkAPI(tc.op, tc.level, tc.x, tc.y, tc.z)
		t.Log(err)
		if tc.isErr {
			if err == nil {
				t.Errorf("case %s: expected error, got nil", tc.op)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %s: expected no error, got %s", tc.op, err)
		}
	}
}
