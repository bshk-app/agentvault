package redact

import "io"

// StreamRedactor masks secrets in a byte stream and forwards masked output to w.
// It retains the trailing bytes that could still grow into a known form, so a value
// split across writes is caught. Always call Close to flush the final tail.
//
// StreamRedactor is fully buffering: it accepts and processes every byte of each
// Write before emitting any masked output. Write therefore reports len(p) as the
// number of bytes consumed in all cases — including when the downstream writer
// fails, in which case it returns (len(p), err). The error reflects the downstream
// failure, not unconsumed input.
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
	cut := r.cutPoint(buf)
	if cut > 0 {
		if _, err := io.WriteString(r.w, r.m.Mask(string(buf[:cut]))); err != nil {
			// All of p was consumed/processed; report it as accepted.
			r.tail = append(r.tail[:0], buf[cut:]...)
			return len(p), err
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

// cutPoint returns the index in buf up to which it is safe to mask and emit now.
// Everything from the cut onward is retained as the tail for the next Write.
//
// It is computed in two steps:
//
//  1. partialCut is the earliest index i such that buf[i:] is a PROPER prefix of
//     some registered form (strictly shorter than that form). Those trailing bytes
//     must be retained because they might still grow into a form on a later write —
//     including a longer form whose own prefix is a complete shorter form. If no
//     such suffix exists, partialCut is len(buf) and the whole buffer is safe.
//
//  2. The cut is then pulled back so it never falls strictly inside a complete form
//     occurrence in buf. While some form occurs at [s, s+len(F)) with
//     s < cut < s+len(F), the cut is lowered to that occurrence's start. This loops
//     until stable; the cut strictly decreases each iteration, so it terminates.
//
// Step 1 prevents prematurely masking a short form that is the prefix of an arriving
// longer form; step 2 guarantees no complete occurrence is split across the boundary.
func (r *StreamRedactor) cutPoint(buf []byte) int {
	cut := r.partialCut(buf)
	s := string(buf)
	for {
		start, ok := r.m.straddleStart(s, cut)
		if !ok {
			return cut
		}
		cut = start // strictly less than the current cut, so this terminates
	}
}

// partialCut returns the earliest index i in the window
// [len(buf)-MaxFormLen+1, len(buf)) such that buf[i:] is a proper prefix of some
// registered form. If none, it returns len(buf).
func (r *StreamRedactor) partialCut(buf []byte) int {
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
