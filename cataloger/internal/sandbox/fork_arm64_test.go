package sandbox

// arm64 has no fork or vfork syscall (libc forks through clone, which the
// clone(SIGCHLD) probe covers).
var forkSyscalls = map[string]uintptr{}
