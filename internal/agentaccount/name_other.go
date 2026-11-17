//go:build !darwin

package agentaccount

// Name is this platform's agent account. The Windows device service runs as
// its virtual service account instead (service/windows.go).
const Name = Linux
