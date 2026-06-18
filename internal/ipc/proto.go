// Package ipc defines AgentVault's newline-delimited JSON-RPC framing.
package ipc

import (
	"bufio"
	"encoding/json"
	"io"
)

// Request is a single client call. Params is method-specific and may be empty.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the daemon's reply. Exactly one of Result/Error is set.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError carries a stable code so the agent can branch (e.g. locked vs denied).
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return e.Message }

// Stable error codes (extended in later phases).
const (
	CodeInternal     = 1
	CodeBadRequest   = 2
	CodeLocked       = 3 // vault locked — agent should ask a human to unlock
	CodeDenied       = 4 // dangerous-tier denied / no presence
	CodeUnauthorized = 5 // peer-credential check failed
	CodeRateLimited  = 6 // issuance rate limit tripped — mass enumeration forced a relock
)

// ResolveParams is the client request for `resolve`. The thin av sends the raw
// agentvault.yaml bytes; avd parses them (av links neither yaml nor backends).
type ResolveParams struct {
	Profile  string `json:"profile"`
	Manifest []byte `json:"manifest"` // raw agentvault.yaml bytes
}

// ResolveResult is the daemon reply: logical name -> secret value. This is the
// sole intended channel for plaintext values; they never appear in any RPCError.
type ResolveResult struct {
	Values map[string]string `json:"values"`
}

// ScrubParams is one chunk of a streamed scrub request. The client loops sending
// chunks (≤256 KiB) via the "scrub" method, then drains the overlap tail at EOF
// via "scrub_flush" (Data is empty/unused for flush). Data carries raw bytes; only
// masked bytes flow back in ScrubResult, never a raw secret.
type ScrubParams struct {
	Data []byte `json:"data,omitempty"`
}

// ScrubResult is the masked output for a scrub/scrub_flush request: only redacted
// bytes, never a raw secret.
type ScrubResult struct {
	Masked []byte `json:"masked,omitempty"`
}

// StatusResult is the daemon reply for unlock/status (and the ok reply for lock).
// SECURITY: it reports ONLY the session's lock state and the remaining unlock
// window — it has no field for an issued value and so can NEVER carry a secret.
type StatusResult struct {
	Locked           bool `json:"locked"`
	RemainingSeconds int  `json:"remaining_seconds"`
}

// Encoder writes newline-delimited JSON values. json.Encoder already appends '\n'.
type Encoder struct{ enc *json.Encoder }

func NewEncoder(w io.Writer) *Encoder { return &Encoder{enc: json.NewEncoder(w)} }
func (e *Encoder) Encode(v any) error { return e.enc.Encode(v) }

// Decoder reads newline-delimited JSON values. A bufio.Scanner bounds line length.
type Decoder struct{ sc *bufio.Scanner }

func NewDecoder(r io.Reader) *Decoder {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1 MiB max line
	return &Decoder{sc: sc}
}

func (d *Decoder) Decode(v any) error {
	if !d.sc.Scan() {
		if err := d.sc.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	return json.Unmarshal(d.sc.Bytes(), v)
}
