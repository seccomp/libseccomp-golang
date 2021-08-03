package seccomp

import (
	"testing"
)

func TestCheckVersion(t *testing.T) {
	for _, tc := range []struct {
		// test input
		op      string
		x, y, z uint
		// test output
		res string // empty string if no error is expected
	}{
		{
			op: "frobnicate", x: 100, y: 99, z: 7,
			res: "frobnicate requires libseccomp >= 100.99.7 (current version: ",
		},
		{
			op: "old-ver", x: 2, y: 2, z: 0, // 2.2.0 is guaranteed to succeed
		},
	} {
		err := checkVersion(tc.op, tc.x, tc.y, tc.z)
		t.Log(err)
		if tc.res != "" { // error expected
			if err == nil {
				t.Errorf("case %s: expected %q-like error, got nil", tc.op, tc.res)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %s: expected no error, got %s", tc.op, err)
		}
	}
}

func TestCheckAPI(t *testing.T) {
	for _, tc := range []struct {
		// test input
		op    string
		level uint
		ver   string
		// test output
		res string // empty string if no error is expected
	}{
		{
			op: "deviate", level: 99, ver: "100.99.88",
			res: "frobnicate requires libseccomp >= 100.99.7 (current version: ",
		},
		{
			op: "api-0", level: 0, // API 0 will succeed
		},
	} {
		err := checkAPI(tc.op, tc.level, tc.ver)
		t.Log(err)
		if tc.res != "" { // error expected
			if err == nil {
				t.Errorf("case %s: expected %q-like error, got nil", tc.op, tc.res)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %s: expected no error, got %s", tc.op, err)
		}
	}
}
