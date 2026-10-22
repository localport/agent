// Package recording holds the terminal session recorder: the asciicast v3
// writer, the segmenter, the sealer (DEK, HPKE wrap, deflate,
// ChaCha20-Poly1305, hash chain, device signatures), the wire codes and
// result types of the edge's recording relay (client.go), the on-disk spool
// (spool.go) and the uploader (uploader.go). Only the spool touches disk.
// Only Uploader.Run starts goroutines; it reaches the network through the
// injected Client, which package tunnel implements.
package recording

import "net/http"

// Refusal codes the edge's recording relay answers with, in the JSON body
// {"code", "retry_after"}.
const (
	CodeNotFound     = "recording_not_found"
	CodeBadRequest   = "recording_bad_request"
	CodeProofInvalid = "recording_proof_invalid"
	CodeConflict     = "recording_conflict"
	CodeOutOfOrder   = "recording_out_of_order"
	CodeMismatch     = "recording_mismatch"
	CodeClosed       = "recording_closed"
	CodeLimit        = "recording_limit"
	CodeQuota        = "recording_quota"
	CodeBusy         = "recording_busy"
	CodeStorage      = "recording_storage"
	CodeUnavailable  = "recording_unavailable"
)

// Reasons a complete body carries when incomplete is true.
const (
	ReasonSpoolFull       = "spool_full"
	ReasonDiskLow         = "disk_low"
	ReasonAgentRestart    = "agent_restart"
	ReasonRecordingFailed = "recording_failed"
)

var statusByCode = map[string]int{
	CodeNotFound:     http.StatusNotFound,
	CodeBadRequest:   http.StatusBadRequest,
	CodeProofInvalid: http.StatusUnauthorized,
	CodeConflict:     http.StatusConflict,
	CodeOutOfOrder:   http.StatusConflict,
	CodeMismatch:     http.StatusConflict,
	CodeClosed:       http.StatusGone,
	CodeLimit:        http.StatusRequestEntityTooLarge,
	CodeQuota:        http.StatusTooManyRequests,
	CodeBusy:         http.StatusServiceUnavailable,
	CodeStorage:      http.StatusBadGateway,
	CodeUnavailable:  http.StatusServiceUnavailable,
}

// Status returns the HTTP status the edge sends with code, and false for a
// code outside the relay's set.
func Status(code string) (int, bool) {
	s, ok := statusByCode[code]
	return s, ok
}
