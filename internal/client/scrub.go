package client

import (
	"encoding/json"
	"io"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// scrubChunkSize bounds each "scrub" request so the WORST-CASE masked reply stays
// under the daemon Decoder's 1 MiB JSON-RPC line cap (ipc.NewDecoder). A naive
// 256 KiB chunk could blow that cap for pathologically short secrets:
//
//	A 1-byte session secret is masked to its placeholder "{{AV:NAME}}" — at least
//	8 bytes ("{{AV:S}}") for a 1-char name. A 256 KiB chunk that is ALL such 1-byte
//	secrets inflates ~8x to ~2 MiB of masked bytes; ScrubResult.Masked ([]byte) is
//	then base64-encoded in JSON (~4/3 = +33%), pushing one reply line to ~2.7 MiB —
//	past the 1 MiB cap, so the client Decoder errors "token too long" and the stream
//	breaks.
//
// Sizing for the worst case: with a conservative placeholder-inflation bound of 8x
// and the base64 factor of 4/3, one masked reply line is at most
//
//	chunk * 8 (inflation) * 4/3 (base64) ≈ chunk * 10.7  (plus tiny JSON framing).
//
// At chunk = 64 KiB that is ~700 KiB — safely under 1 MiB with headroom for the
// framing and for names a few bytes longer than 1 char. So 64 KiB is the largest
// power-of-two chunk that keeps every reply within the cap for any input.
const scrubChunkSize = 64 * 1024

// Scrub streams in through the daemon's per-connection layer-2 redactor and writes
// the masked result to out. All masking happens daemon-side; the client only ships
// raw bytes and writes back masked bytes (so av stays thin — no redact dependency).
//
// Because the daemon keeps per-connection scrub state (a StreamRedactor whose
// retained tail catches a secret split across chunks), every "scrub"/"scrub_flush"
// for one stream MUST travel over the SAME connection — Scrub dials once and reuses
// the connection for the whole stream, draining the overlap tail with "scrub_flush"
// at EOF.
func (c *Client) Scrub(in io.Reader, out io.Writer) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	enc := ipc.NewEncoder(conn)
	dec := ipc.NewDecoder(conn)

	send := func(id uint64, method string, data []byte) error {
		params, _ := json.Marshal(ipc.ScrubParams{Data: data})
		if err := enc.Encode(ipc.Request{ID: id, Method: method, Params: params}); err != nil {
			return err
		}
		var resp ipc.Response
		if err := dec.Decode(&resp); err != nil {
			return err
		}
		if resp.Error != nil {
			return resp.Error // non-secret message; carries a stable Code
		}
		var r ipc.ScrubResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return err
		}
		if len(r.Masked) > 0 {
			if _, err := out.Write(r.Masked); err != nil {
				return err
			}
		}
		return nil
	}

	buf := make([]byte, scrubChunkSize)
	var id uint64
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			id++
			if err := send(id, "scrub", buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	id++
	return send(id, "scrub_flush", nil)
}
