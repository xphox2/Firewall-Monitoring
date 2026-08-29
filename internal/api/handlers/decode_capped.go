package handlers

import (
	"encoding/json"
	"net/http"

	"firewall-mon/internal/api/response"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// decodeCappedArray streams a JSON array from the request body, decoding AT MOST
// capN elements into a slice of cap capN.
//
// AUDIT-196: every Receive* telemetry handler used to `c.ShouldBindJSON(&items)`
// — a FULL-array decode with no count limit — and only THEN cap the slice
// (truncateProbeBatch / `items[:cap]`). Because the cap reslices rather than
// copies, the entire decoded backing array stayed live: a 5MB body of empty
// `{}` objects amplifies to ~670MB–1GB of decoded structs BEFORE the 1000-item
// cap ever applies, so the cap gave false safety. This decoder stops
// materializing structs once capN is reached — the tail is consumed as raw
// bytes, one element at a time (bounded memory), purely to keep `total` exact
// for the truncation alert. Peak live memory is capN structs, not the whole
// array.
//
// It returns the decoded head (len ≤ capN), the true number of array elements
// seen (`total`; > capN iff the batch was truncated), and ok. On a malformed,
// non-array, empty, or oversize body it writes the same 400 the handlers'
// ShouldBindJSON path emitted — response.Error("Invalid JSON") — and returns
// ok=false. A JSON `null` body decodes as an empty batch (ok=true, total=0),
// matching ShouldBindJSON(&slice), which leaves the slice nil without erroring.
// The body is already capped at 5MB by BodySizeLimitPerPath's MaxBytesReader;
// the decoder reads through it, so an oversize body surfaces here as a decode
// error → 400 (unchanged from ShouldBindJSON).
func decodeCappedArray[T any](c *gin.Context, capN int) (out []T, total int, ok bool) {
	fail := func() ([]T, int, bool) {
		c.JSON(http.StatusBadRequest, response.Error("Invalid JSON"))
		return nil, 0, false
	}
	if c.Request == nil || c.Request.Body == nil {
		return fail()
	}
	dec := json.NewDecoder(c.Request.Body)

	// First token: '[' opens an array; a bare JSON null is an empty batch (matches
	// ShouldBindJSON(&slice) → nil slice, no error); anything else is a 400.
	tok, err := dec.Token()
	if err != nil {
		return fail()
	}
	if tok == nil {
		return nil, 0, true
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim || delim != '[' {
		return fail()
	}

	out = make([]T, 0, capN)
	for dec.More() {
		if len(out) < capN {
			var e T
			if err := dec.Decode(&e); err != nil {
				return fail()
			}
			out = append(out, e)
			total++
			continue
		}
		// Cap reached: keep counting the tail WITHOUT retaining it, so the
		// truncation alert's item count stays exact while peak memory stays at
		// capN structs. A malformed / oversize tail is a bad body just like it
		// was pre-fix (ShouldBindJSON would have 400'd the whole array), so fail.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fail()
		}
		total++
	}
	// dec.More() returns false on a READ error too — EOF from a dropped/truncated
	// body, or MaxBytesReader's "request body too large" landing at an element
	// boundary. Without this check a body cut mid-array (`[{...},{...}` with no
	// closing `]`) would return a PARTIAL batch as ok=true; the handler would save
	// it, return 200, and markBatchIfOK would record the idempotency key — so the
	// collector's retry is deduped and the tail is lost forever with NO truncation
	// alert. Consuming the closing `]` restores the pre-fix 400: a well-formed
	// array ends on the `]` delim (no error), while a truncated or oversize body
	// errors here. Trailing garbage after `]` is left unread, matching the lenient
	// ShouldBindJSON behavior.
	if _, err := dec.Token(); err != nil {
		return fail()
	}
	return out, total, true
}

// decodeCappedProbeBatch is the probe-ingest front door for the AUDIT-196 fix: it
// streams+caps the request body (see decodeCappedArray) and, when the batch
// overshot capN, emits the same dropped-tail log + PROBE_DATA_TRUNCATED alert the
// old truncateProbeBatch reslice did (recordProbeTruncation). ok=false means a
// 400 was already written and the caller must return immediately.
func decodeCappedProbeBatch[T any](h *Handler, c *gin.Context, probe *models.Probe, kind string, capN int) (out []T, ok bool) {
	out, total, ok := decodeCappedArray[T](c, capN)
	if !ok {
		return nil, false
	}
	if total > capN {
		h.recordProbeTruncation(probe, kind, total, capN)
	}
	return out, true
}
