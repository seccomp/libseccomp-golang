# libseccomp-golang

.PHONY: all check check-build check-syntax fix-syntax vet test lint

all: check-build

check: vet test

check-build:
	go build

check-syntax:
	gofmt -d .

fix-syntax:
	gofmt -w .

vet:
	go vet -v

# Previous bugs have made the tests freeze until the timeout. Golang default
# timeout for tests is 10 minutes, which is too long, considering current tests
# can be executed in less than 1 second. Reduce the timeout, so problems can
# be noticed earlier in the CI.
TEST_TIMEOUT=10s

# Some tests run with SetTsync(false) and some tests with SetTsync(true). Once
# the threads are not using the same seccomp filters anymore, the kernel will
# refuse to use Tsync, causing next tests to fail. This issue could be left
# unnoticed if the test with SetTsync(false) is executed last.
#
# Run tests twice ensure that no test leave the testing process in a state
# unable to run following tests, regardless of the subset of tests selected.
TEST_COUNT=2

test:
	go test -v -timeout $(TEST_TIMEOUT) -count $(TEST_COUNT)

lint:
	@$(if $(shell which golint),true,$(error "install golint and include it in your PATH"))
	golint -set_exit_status
