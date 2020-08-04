// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"gvisor.dev/gvisor/runsc/flag"
)

var (
	// Although these flags are not part of the OCI spec, they are used by
	// Docker, and thus should not be changed.
	_ = flag.String("root", "", "root directory for storage of container state.")
	_ = flag.String("log", "", "file path where internal debug information is written, default is stdout.")
	_ = flag.String("log-format", "text", "log format: text (default), json, or json-k8s.")
	_ = flag.Bool("debug", false, "enable debug logging.")

	// These flags are unique to runsc, and are used to configure parts of the
	// system that are not covered by the runtime spec.

	// Debugging flags.
	_ = flag.String("debug-log", "", "additional location for logs. If it ends with '/', log files are created inside the directory with default names. The following variables are available: %TIMESTAMP%, %COMMAND%.")
	_ = flag.String("panic-log", "", "file path were panic reports and other Go's runtime messages are written.")
	_ = flag.Bool("log-packets", false, "enable network packet logging.")
	_ = flag.String("debug-log-format", "text", "log format: text (default), json, or json-k8s.")
	_ = flag.Bool("alsologtostderr", false, "send log messages to stderr.")

	// Debugging flags: strace related
	_ = flag.Bool("strace", false, "enable strace.")
	_ = flag.String("strace-syscalls", "", "comma-separated list of syscalls to trace. If --strace is true and this list is empty, then all syscalls will be traced.")
	_ = flag.Uint("strace-log-size", 1024, "default size (in bytes) to log data argument blobs.")

	// Flags that control sandbox runtime behavior.
	_ = flag.String("platform", "ptrace", "specifies which platform to use: ptrace (default), kvm.")
	_ = flag.String("network", "sandbox", "specifies which network to use: sandbox (default), host, none. Using network inside the sandbox is more secure because it's isolated from the host network.")
	_ = flag.Bool("gso", true, "enable hardware segmentation offload if it is supported by a network device.")
	_ = flag.Bool("software-gso", true, "enable software segmentation offload when hardware offload can't be enabled.")
	_ = flag.Bool("tx-checksum-offload", false, "enable TX checksum offload.")
	_ = flag.Bool("rx-checksum-offload", true, "enable RX checksum offload.")
	_ = flag.String("qdisc", "fifo", "specifies which queueing discipline to apply by default to the non loopback nics used by the sandbox.")
	_ = flag.String("file-access", "exclusive", "specifies which filesystem to use for the root mount: exclusive (default), shared. Volume mounts are always shared.")
	_ = flag.Bool("fsgofer-host-uds", false, "allow the gofer to mount Unix Domain Sockets.")
	_ = flag.Bool("overlay", false, "wrap filesystem mounts with writable overlay. All modifications are stored in memory inside the sandbox.")
	_ = flag.Bool("overlayfs-stale-read", true, "assume root mount is an overlay filesystem")
	_ = flag.String("watchdog-action", "log", "sets what action the watchdog takes when triggered: log (default), panic.")
	_ = flag.Int("panic-signal", -1, "register signal handling that panics. Usually set to SIGUSR2(12) to troubleshoot hangs. -1 disables it.")
	_ = flag.Bool("profile", false, "prepares the sandbox to use Golang profiler. Note that enabling profiler loosens the seccomp protection added to the sandbox (DO NOT USE IN PRODUCTION).")
	_ = flag.Bool("net-raw", false, "enable raw sockets. When false, raw sockets are disabled by removing CAP_NET_RAW from containers (`runsc exec` will still be able to utilize raw sockets). Raw sockets allow malicious containers to craft packets and potentially attack the network.")
	_ = flag.Int("num-network-channels", 1, "number of underlying channels(FDs) to use for network link endpoints.")
	_ = flag.Bool("rootless", false, "it allows the sandbox to be started with a user that is not root. Sandbox and Gofer processes may run with same privileges as current user.")
	_ = flag.String("ref-leak-mode", "disabled", "sets reference leak check mode: disabled (default), log-names, log-traces.")
	_ = flag.Bool("cpu-num-from-quota", false, "set cpu number to cpu quota (least integer greater or equal to quota value, but not less than 2)")
	_ = flag.Bool("vfs2", false, "TEST ONLY; use while VFSv2 is landing. This uses the new experimental VFS layer.")
	_ = flag.Bool("fuse", false, "TEST ONLY; use while FUSE in VFSv2 is landing. This allows the use of the new experimental FUSE filesystem.")

	// Test flags, not to be used outside tests, ever.
	_ = flag.Bool("TESTONLY-unsafe-nonroot", false, "TEST ONLY; do not ever use! This skips many security measures that isolate the host from the sandbox.")
	_ = flag.String("TESTONLY-test-name-env", "", "TEST ONLY; do not ever use! Used for automated tests to improve logging.")
)

func NewFromFlags() (*Config, error) {
	conf := &Config{}

	obj := reflect.ValueOf(conf).Elem()
	st := obj.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("flag")
		if !ok {
			// No flag set for this field.
			continue
		}
		flag := flag.CommandLine.Lookup(name)
		if flag == nil {
			panic(name)
		}

		// Cast in case underlying type is different, e.q. type Foo string.
		x := reflect.ValueOf(flag.Value.Get()).Convert(obj.Field(i).Type())
		obj.Field(i).Set(x)
	}

	if len(conf.RootDir) == 0 {
		// If not set, set default root dir to something (hopefully) user-writeable.
		conf.RootDir = "/var/run/runsc"
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			conf.RootDir = filepath.Join(runtimeDir, "runsc")
		}
	}

	if err := conf.validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

func (c *Config) ToFlags() []string {
	var rv []string

	obj := reflect.ValueOf(c).Elem()
	st := obj.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("flag")
		if !ok {
			// No flag set for this field.
			continue
		}
		val := getVal(obj.Field(i))

		flag := flag.CommandLine.Lookup(name)
		if flag == nil {
			panic(name)
		}
		if val == flag.DefValue {
			continue
		}
		rv = append(rv, fmt.Sprintf("--%s=%s", flag.Name, val))
	}
	return rv
}

func getVal(field reflect.Value) string {
	if str, ok := field.Interface().(fmt.Stringer); ok {
		return str.String()
	}
	switch field.Kind() {
	case reflect.Bool:
		return strconv.FormatBool(field.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(field.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(field.Uint(), 10)
	case reflect.String:
		return field.String()
	default:
		panic("unknown type " + field.Kind().String())
	}
}
