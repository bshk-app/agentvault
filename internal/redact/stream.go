package redact

import "io"

// StreamRedactor masks secrets in a byte stream and forwards masked output to w.
// It retains the trailing bytes that could still grow into a known form, so a value
// split across writes is caught. Always call Close to flush the final tail.
type StreamRedactor struct {
	m    *Matcher
	w    io.Writer
	tail []byte
}

func NewStreamRedactor(m *Matcher, w io.Writer) *StreamRedactor {
	return &StreamRedactor{m: m, w: w}
}

func (r *StreamRedactor) Write(p []byte) (int, error) {
	buf := append(r.tail, p...)
	cut := r.retainStart(buf)
	if cut > 0 {
		if _, err := io.WriteString(r.w, r.m.Mask(string(buf[:cut]))); err != nil {
			return 0, err
		}
	}
	r.tail = append(r.tail[:0], buf[cut:]...)
	return len(p), nil
}

// Close flushes the retained tail, masking it fully (no more data can arrive).
func (r *StreamRedactor) Close() error {
	if len(r.tail) == 0 {
		return nil
	}
	_, err := io.WriteString(r.w, r.m.Mask(string(r.tail)))
	r.tail = nil
	return err
}

// retainStart returns the earliest index i such that buf[i:] is a proper prefix of
// some known form. Everything before i is safe to mask and emit now. If nothing at
// the tail could grow into a form, the whole buffer is safe (returns len(buf)).
func (r *StreamRedactor) retainStart(buf []byte) int {
	start := len(buf) - r.m.MaxFormLen() + 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(buf); i++ {
		if r.m.hasFormWithPrefix(string(buf[i:])) {
			return i
		}
	}
	return len(buf)
}
