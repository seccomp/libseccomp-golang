// +build linux

package seccomp

import "os"

// #cgo pkg-config: libseccomp
// #include <stdlib.h>
// #include <seccomp.h>
import "C"

// ScmpNotifReq is a seccomp notifier request
type ScmpNotifReq struct {
	inner C.seccomp_notif
}

// ScmpNotifResp is a seccomp notifier response
type ScmpNotifResp struct {
	inner C.seccomp_notif_resp
}

// NotifyAlloc creates a new pair of notification request/response structures.
// See libseccomp API `seccomp_notify_alloc()`.
func NotifyAlloc() (*ScmpNotifReq, *ScmpNotifResp, error) {
	req := &ScmpNotifReq{}
	resp := &ScmpNotifResp{}
	if ret := C.seccomp_notify_alloc(req.inner, resp.inner); ret != 0 {
		return nil, nil, errRc(ret)
	}
	return req, resp, nil
}

// NotifyFree will cleanup a pair of notification request/response structures.
// See libseccomp API `seccomp_notify_free()`.
func NotifyFree(req *ScmpNotifReq, resp *ScmpNotifResp) {
	C.seccomp_notify_free(req.inner, resp.inner)
}

// Receive tries to get a notification from a seccomp notification file.
// See libseccomp API `seccomp_notify_receive()`.
func (s *ScmpNotifReq) Receive(file *os.File) error {
	if ret := C.seccomp_notify_receive(file.Fd(), s.inner); ret != 0 {
		return errRc(ret)
	}
	return nil
}

// Respond tries to send a notification to a seccomp notification file.
// See libseccomp API `seccomp_notify_respond()`.
func (s *ScmpNotifResp) Respond(file *os.File) error {
	if ret := C.seccomp_notify_respond(file.Fd(), s.inner); ret != 0 {
		return errRc(ret)
	}
	return nil
}

// NotifyIDValid checks if a notification id is still valid.
// See libseccomp API `seccomp_notify_id_valid()`.
func NotifyIDValid(file *os.File, id uint64) bool {
	return C.seccomp_notify_id_valid(file.Fd(), C.uint64_t(id)) == 0
}

// NotifyFd returns the notification file from a filter that has already been
// loaded.
// See libseccomp API `seccomp_notify_fd()`.
func NotifyFd(filter *ScmpFilter) *os.File {
	fd := C.seccomp_notify_fd(filter.filterCtx)
	return os.NewFile(fd, "")
}
