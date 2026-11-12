// Package childproc holds the per-platform process and PTY steps shared by
// the session helper and the CLI's agent child: observing a child's exit
// without reaping it, so its pid and process group number stay reserved for
// the signals sent until the reap, and revoking a PTY slave so a blocked
// master Read ends.
package childproc
