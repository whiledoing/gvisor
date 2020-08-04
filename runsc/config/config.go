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

// Package config provides basic infrastructure to set configuration settings
// for runsc. The configuration is set by flags to the command line. They can
// also propagate to a different process using the same flags.
package config

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
)

// Config holds configuration that is not part of the runtime spec.
//
// Follow these steps to add a new flag:
//   1. Create a new field in Config.
//   2. Add a field tag with the flag name
//   3. Register a new flag in flags.go, with name and description
//   4. Add any necessary validation into validate()
//   5. If adding an enum, follow the same pattern as FileAccessType
//
type Config struct {
	// RootDir is the runtime root directory.
	RootDir string `flag:"root"`

	// Debug indicates that debug logging should be enabled.
	Debug bool `flag:"debug"`

	// LogFilename is the filename to log to, if not empty.
	LogFilename string `flag:"log"`

	// LogFormat is the log format.
	LogFormat string `flag:"log-format"`

	// DebugLog is the path to log debug information to, if not empty.
	DebugLog string `flag:"debug-log"`

	// PanicLog is the path to log GO's runtime messages, if not empty.
	PanicLog string `flag:"panic-log"`

	// DebugLogFormat is the log format for debug.
	DebugLogFormat string `flag:"debug-log-format"`

	// FileAccess indicates how the filesystem is accessed.
	FileAccess FileAccessType `flag:"file-access"`

	// Overlay is whether to wrap the root filesystem in an overlay.
	Overlay bool `flag:"overlay"`

	// FSGoferHostUDS enables the gofer to mount a host UDS.
	FSGoferHostUDS bool `flag:"fsgofer-host-uds"`

	// Network indicates what type of network to use.
	Network NetworkType `flag:"network"`

	// EnableRaw indicates whether raw sockets should be enabled. Raw
	// sockets are disabled by stripping CAP_NET_RAW from the list of
	// capabilities.
	EnableRaw bool `flag:"net-raw"`

	// HardwareGSO indicates that hardware segmentation offload is enabled.
	HardwareGSO bool `flag:"gso"`

	// SoftwareGSO indicates that software segmentation offload is enabled.
	SoftwareGSO bool `flag:"software-gso"`

	// TXChecksumOffload indicates that TX Checksum Offload is enabled.
	TXChecksumOffload bool `flag:"tx-checksum-offload"`

	// RXChecksumOffload indicates that RX Checksum Offload is enabled.
	RXChecksumOffload bool `flag:"rx-checksum-offload"`

	// QDisc indicates the type of queuening discipline to use by default
	// for non-loopback interfaces.
	QDisc QueueingDiscipline `flag:"qdisc"`

	// LogPackets indicates that all network packets should be logged.
	LogPackets bool `flag:"log-packets"`

	// Platform is the platform to run on.
	Platform string `flag:"platform"`

	// Strace indicates that strace should be enabled.
	Strace bool `flag:"strace"`

	// StraceSyscalls is the set of syscalls to trace (comma-separated values).
	// If StraceEnable is true and this string is empty, then all syscalls will
	// be traced.
	StraceSyscalls string `flag:"strace-syscalls"`

	// StraceLogSize is the max size of data blobs to display.
	StraceLogSize uint `flag:"strace-log-size"`

	// DisableSeccomp indicates whether seccomp syscall filters should be
	// disabled. Pardon the double negation, but default to enabled is important.
	DisableSeccomp bool

	// WatchdogAction sets what action the watchdog takes when triggered.
	WatchdogActionStr string `flag:"watchdog-action"`

	// PanicSignal registers signal handling that panics. Usually set to
	// SIGUSR2(12) to troubleshoot hangs. -1 disables it.
	PanicSignal int `flag:"panic-signal"`

	// ProfileEnable is set to prepare the sandbox to be profiled.
	ProfileEnable bool `flag:"profile"`

	// RestoreFile is the path to the saved container image
	RestoreFile string

	// NumNetworkChannels controls the number of AF_PACKET sockets that map
	// to the same underlying network device. This allows netstack to better
	// scale for high throughput use cases.
	NumNetworkChannels int `flag:"num-network-channels"`

	// Rootless allows the sandbox to be started with a user that is not root.
	// Defense is depth measures are weaker with rootless. Specifically, the
	// sandbox and Gofer process run as root inside a user namespace with root
	// mapped to the caller's user.
	Rootless bool `flag:"rootless"`

	// AlsoLogToStderr allows to send log messages to stderr.
	AlsoLogToStderr bool `flag:"alsologtostderr"`

	// ReferenceLeakMode sets reference leak check mode
	ReferenceLeakStr string `flag:"ref-leak-mode"`

	// OverlayfsStaleRead instructs the sandbox to assume that the root mount
	// is on a Linux overlayfs mount, which does not necessarily preserve
	// coherence between read-only and subsequent writable file descriptors
	// representing the "same" file.
	OverlayfsStaleRead bool `flag:"overlayfs-stale-read"`

	// CPUNumFromQuota sets CPU number count to available CPU quota, using
	// least integer value greater than or equal to quota.
	//
	// E.g. 0.2 CPU quota will result in 1, and 1.9 in 2.
	CPUNumFromQuota bool `flag:"cpu-num-from-quota"`

	// Enables VFS2.
	VFS2 bool `flag:"vfs2"`

	// Enables FUSE usage.
	FUSE bool `flag:"fuse"`

	// TestOnlyAllowRunAsCurrentUserWithoutChroot should only be used in
	// tests. It allows runsc to start the sandbox process as the current
	// user, and without chrooting the sandbox process. This can be
	// necessary in test environments that have limited capabilities.
	TestOnlyAllowRunAsCurrentUserWithoutChroot bool `flag:"TESTONLY-unsafe-nonroot"`

	// TestOnlyTestNameEnv should only be used in tests. It looks up for the
	// test name in the container environment variables and adds it to the debug
	// log file name. This is done to help identify the log with the test when
	// multiple tests are run in parallel, since there is no way to pass
	// parameters to the runtime from docker.
	TestOnlyTestNameEnv string `flag:"TESTONLY-test-name-env"`
}

func (c *Config) validate() error {
	if err := c.checkFileAccess(); err != nil {
		return err
	}
	if c.FileAccess == FileAccessShared && c.Overlay {
		return fmt.Errorf("overlay flag is incompatible with shared file access")
	}

	if err := c.checkNetworkType(); err != nil {
		return err
	}
	if err := c.checkQueueingDiscipline(); err != nil {
		return err
	}
	if _, err := c.parseWatchdogAction(); err != nil {
		return err
	}
	if _, err := c.parseRefsLeakMode(); err != nil {
		return err
	}
	if c.NumNetworkChannels <= 0 {
		return fmt.Errorf("num_network_channels must be > 0, got: %d", c.NumNetworkChannels)
	}
	return nil
}

// FileAccessType tells how the filesystem is accessed.
type FileAccessType string

const (
	// FileAccessShared sends IO requests to a Gofer process that validates the
	// requests and forwards them to the host.
	FileAccessShared FileAccessType = "shared"

	// FileAccessExclusive is the same as FileAccessShared, but enables
	// extra caching for improved performance. It should only be used if
	// the sandbox has exclusive access to the filesystem.
	FileAccessExclusive FileAccessType = "exclusive"
)

func (c *Config) checkFileAccess() error {
	switch c.FileAccess {
	case FileAccessShared, FileAccessExclusive:
		return nil
	default:
		return fmt.Errorf("invalid file access type %q", c.FileAccess)
	}
}

// NetworkType tells which network stack to use.
type NetworkType string

const (
	// NetworkSandbox uses internal network stack, isolated from the host.
	NetworkSandbox NetworkType = "sandbox"

	// NetworkHost redirects network related syscalls to the host network.
	NetworkHost NetworkType = "host"

	// NetworkNone sets up just loopback using netstack.
	NetworkNone NetworkType = "none"
)

func (c *Config) checkNetworkType() error {
	switch c.Network {
	case NetworkSandbox, NetworkHost, NetworkNone:
		return nil
	default:
		return fmt.Errorf("invalid network type %q", c.Network)
	}
}

// QueueingDiscipline is used to specify the kind of Queueing Discipline to
// apply for a give FDBasedLink.
type QueueingDiscipline string

const (
	// QDiscNone disables any queueing for the underlying FD.
	QDiscNone QueueingDiscipline = "none"

	// QDiscFIFO applies a simple fifo based queue to the underlying FD.
	QDiscFIFO QueueingDiscipline = "fifo"
)

func (c *Config) checkQueueingDiscipline() error {
	switch c.QDisc {
	case QDiscNone, QDiscFIFO:
		return nil
	default:
		return fmt.Errorf("invalid qdisc %q", c.QDisc)
	}
}

func (c *Config) parseWatchdogAction() (watchdog.Action, error) {
	switch c.WatchdogActionStr {
	case "log", "logwarning":
		return watchdog.LogWarning, nil
	case "panic":
		return watchdog.Panic, nil
	default:
		return 0, fmt.Errorf("invalid watchdog action %q", c.WatchdogActionStr)
	}
}

func (c *Config) WatchdogAction() watchdog.Action {
	wa, err := c.parseWatchdogAction()
	if err != nil {
		panic(err)
	}
	return wa
}

func (c *Config) parseRefsLeakMode() (refs.LeakMode, error) {
	switch c.ReferenceLeakStr {
	case "disabled":
		return refs.NoLeakChecking, nil
	case "log-names":
		return refs.LeaksLogWarning, nil
	case "log-traces":
		return refs.LeaksLogTraces, nil
	default:
		return 0, fmt.Errorf("invalid ref leak mode %q", c.ReferenceLeakStr)
	}
}

func (c *Config) RefsLeakMode() refs.LeakMode {
	lm, err := c.parseRefsLeakMode()
	if err != nil {
		panic(err)
	}
	return lm
}
