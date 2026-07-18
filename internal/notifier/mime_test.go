package notifier

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
)

// parseMsg parses a built message with the stdlib the way an MTA/client would.
func parseMsg(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	return msg
}

type parsedPart struct {
	mediaType string
	params    map[string]string
	header    map[string][]string
	body      []byte // decoded per Content-Transfer-Encoding
	children  []parsedPart
}

// parseEntity recursively decodes a MIME entity (QP/base64 aware).
func parseEntity(t *testing.T, mediaType string, params map[string]string, header map[string][]string, body io.Reader) parsedPart {
	t.Helper()
	p := parsedPart{mediaType: mediaType, params: params, header: header}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			// NextRawPart, NOT NextPart: NextPart transparently QP-decodes
			// and HIDES the Content-Transfer-Encoding header — this test
			// exists to assert that header, so decode manually.
			part, err := mr.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("NextRawPart under %s: %v", mediaType, err)
			}
			ct := part.Header.Get("Content-Type")
			mt, ps, err := mime.ParseMediaType(ct)
			if err != nil {
				t.Fatalf("part Content-Type %q: %v", ct, err)
			}
			var reader io.Reader = part
			switch strings.ToLower(part.Header.Get("Content-Transfer-Encoding")) {
			case "quoted-printable":
				reader = quotedprintable.NewReader(part)
			case "base64":
				reader = base64Decoder(part)
			}
			p.children = append(p.children, parseEntity(t, mt, ps, map[string][]string(part.Header), reader))
		}
		return p
	}
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read %s body: %v", mediaType, err)
	}
	p.body = data
	return p
}

func base64Decoder(r io.Reader) io.Reader {
	// The builder wraps base64 at 76 cols with CRLF; strip whitespace first.
	raw, _ := io.ReadAll(r)
	clean := strings.NewReplacer("\r", "", "\n", "").Replace(string(raw))
	dec, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return strings.NewReader("\x00DECODE-ERROR: " + err.Error())
	}
	return bytes.NewReader(dec)
}

// TestBuildMIMEMessage_AlternativeTree pins the canonical no-image shape:
// multipart/alternative with text/plain FIRST and text/html LAST (RFC 2046
// preference order), both quoted-printable, QP round-trip exact.
func TestBuildMIMEMessage_AlternativeTree(t *testing.T) {
	textBody := "PLAIN threshold=90 naïve café\r\n"
	htmlBody := "<html><body>HTML threshold=90 — naïve café</body></html>"
	raw, err := buildMIMEMessage("from@x.net", "to@x.net", "Subject A", textBody, htmlBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMsg(t, raw)
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("top Content-Type = %q (err %v), want multipart/alternative", mt, err)
	}
	root := parseEntity(t, mt, params, map[string][]string(msg.Header), msg.Body)
	if len(root.children) != 2 {
		t.Fatalf("alternative children = %d, want 2", len(root.children))
	}
	if root.children[0].mediaType != "text/plain" || root.children[1].mediaType != "text/html" {
		t.Fatalf("child order = %s, %s — plaintext must come FIRST", root.children[0].mediaType, root.children[1].mediaType)
	}
	for _, c := range root.children {
		if cte := c.header["Content-Transfer-Encoding"]; len(cte) != 1 || cte[0] != "quoted-printable" {
			t.Errorf("%s CTE = %v, want quoted-printable", c.mediaType, cte)
		}
	}
	if got := string(root.children[0].body); got != textBody {
		t.Errorf("plain QP round-trip mismatch:\n got %q\nwant %q", got, textBody)
	}
	if got := string(root.children[1].body); got != htmlBody {
		t.Errorf("html QP round-trip mismatch:\n got %q\nwant %q", got, htmlBody)
	}
}

// TestBuildMIMEMessage_RelatedOverAlternative pins the full image tree:
// multipart/related; type="multipart/alternative" whose first child is the
// alternative pair and whose siblings are the inline base64 PNGs with
// bracketed Content-IDs.
func TestBuildMIMEMessage_RelatedOverAlternative(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	atts := []Attachment{{ContentID: "chart1", Data: png, MIMEType: "image/png"}}
	raw, err := buildMIMEMessage("from@x.net", "to@x.net", "Subject B", "PLAIN", `<img src="cid:chart1">`, atts)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMsg(t, raw)
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" {
		t.Fatalf("top Content-Type = %q (err %v), want multipart/related", mt, err)
	}
	if params["type"] != "multipart/alternative" {
		t.Fatalf(`related type param = %q, want "multipart/alternative"`, params["type"])
	}
	root := parseEntity(t, mt, params, map[string][]string(msg.Header), msg.Body)
	if len(root.children) != 2 {
		t.Fatalf("related children = %d, want 2 (alternative + png)", len(root.children))
	}
	alt := root.children[0]
	if alt.mediaType != "multipart/alternative" || len(alt.children) != 2 ||
		alt.children[0].mediaType != "text/plain" || alt.children[1].mediaType != "text/html" {
		t.Fatalf("first child is not a well-formed alternative: %+v", alt.mediaType)
	}
	img := root.children[1]
	if img.mediaType != "image/png" {
		t.Fatalf("second child = %s, want image/png", img.mediaType)
	}
	if cid := img.header["Content-Id"]; len(cid) != 1 || cid[0] != "<chart1>" {
		t.Errorf("Content-ID = %v, want <chart1> (bracketed)", cid)
	}
	if disp := img.header["Content-Disposition"]; len(disp) != 1 || !strings.HasPrefix(disp[0], "inline") {
		t.Errorf("Content-Disposition = %v, want inline", disp)
	}
	if !bytes.Equal(img.body, png) {
		t.Errorf("base64 round-trip mismatch: got %d bytes, want %d", len(img.body), len(png))
	}
	// Line-length discipline: base64 payload lines wrap at 76 (RFC 2045);
	// everything else (headers with long boundary params are fine — Go's own
	// mime/multipart emits them) stays under the RFC 5322 hard cap of 998.
	b64Line := func(s string) bool {
		if s == "" {
			return false
		}
		return strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == ""
	}
	for _, line := range strings.Split(string(raw), "\r\n") {
		if b64Line(line) && len(line) > 76 {
			t.Errorf("base64 line exceeds 76 chars: %d", len(line))
		}
		if len(line) > 998 {
			t.Errorf("line exceeds RFC 5322 hard limit: %d chars: %.40s…", len(line), line)
		}
	}
}

// TestBuildMIMEMessage_LegacyShapes pins the blank-textBody degradations:
// bare QP text/html without images (the 8bit path is retired — uniform QP),
// and related-over-html with images.
func TestBuildMIMEMessage_LegacyShapes(t *testing.T) {
	raw, err := buildMIMEMessage("f@x.net", "t@x.net", "S", "", "<p>hi threshold=90</p>", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMsg(t, raw)
	mt, _, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "text/html" {
		t.Fatalf("no-text no-img top type = %q, want text/html", mt)
	}
	if cte := msg.Header.Get("Content-Transfer-Encoding"); cte != "quoted-printable" {
		t.Fatalf("CTE = %q, want quoted-printable (8bit retired)", cte)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if string(body) != "<p>hi threshold=90</p>" {
		t.Errorf("QP round-trip mismatch: %q", body)
	}

	raw, err = buildMIMEMessage("f@x.net", "t@x.net", "S", "", `<img src="cid:c">`,
		[]Attachment{{ContentID: "c", Data: []byte{1, 2, 3}, MIMEType: "image/png"}})
	if err != nil {
		t.Fatal(err)
	}
	msg = parseMsg(t, raw)
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/related" || params["type"] != "text/html" {
		t.Fatalf("no-text with-img top = %q type=%q, want related over text/html", mt, params["type"])
	}
	root := parseEntity(t, mt, params, map[string][]string(msg.Header), msg.Body)
	if len(root.children) != 2 || root.children[0].mediaType != "text/html" || root.children[1].mediaType != "image/png" {
		t.Fatalf("legacy related shape wrong: %d children", len(root.children))
	}
}

// TestBuildMIMEMessage_HeaderSanitized pins CRLF stripping on all address /
// subject headers (header-injection guard, AUDIT-014 family).
func TestBuildMIMEMessage_HeaderSanitized(t *testing.T) {
	raw, err := buildMIMEMessage("f@x.net", "t@x.net", "evil\r\nBcc: spam@x.net", "T", "<p>h</p>", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMsg(t, raw)
	if msg.Header.Get("Bcc") != "" {
		t.Fatal("subject CRLF injection produced a Bcc header")
	}
	if !strings.Contains(msg.Header.Get("Subject"), "evil") {
		t.Fatalf("subject mangled: %q", msg.Header.Get("Subject"))
	}
}
