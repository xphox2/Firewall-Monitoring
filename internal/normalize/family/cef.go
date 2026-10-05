package family

import "strings"

// CEF is one ArcSight Common Event Format record:
//
//	CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//
// Header fields are split on unescaped '|' (`\|` is a literal pipe). The
// extension is `key=value` pairs whose VALUES may contain unescaped spaces
// (UniFi writes `msg=Admin alice logged in`), so a value runs until the next
// ` key=` lookahead rather than the next space. `\=`, `\\`, `\n`, `\r` are
// unescaped in values. Ext keys are lowercased so a rule field
// (`unifipolicyname`) can match them — the engine lowercases rule fields.
type CEF struct {
	Version, Vendor, Product, DeviceVersion string
	SignatureID, Name, Severity             string
	Ext                                     map[string]string
}

// cefPrefix is the record marker; a leading `TAG: ` or re-joined syslog
// header in front of it is tolerated (see HasCEF).
const cefPrefix = "CEF:"

// HasCEF is the cheap gate: the record marker is at the start, or after a
// space within the first cefSniffLen bytes with nothing but header-like
// tokens before it (no '='). A key=value line whose quoted value mentions a
// CEF record (`msg="saw CEF:0|…"`) is not a CEF record — the FortiGate order
// tries CEF first, so this gate must not steal FortiOS lines.
func HasCEF(s string) bool {
	return cefStart(s) >= 0
}

const cefSniffLen = 160

func cefStart(s string) int {
	if strings.HasPrefix(s, cefPrefix) {
		return 0
	}
	lim := len(s)
	if lim > cefSniffLen {
		lim = cefSniffLen
	}
	i := strings.Index(s[:lim], " "+cefPrefix)
	if i < 0 || strings.IndexByte(s[:i], '=') >= 0 {
		return -1
	}
	return i + 1
}

// ParseCEF tokenizes a CEF record. ok=false when the marker is absent or the
// header has fewer than 7 fields.
func ParseCEF(s string) (CEF, bool) {
	start := cefStart(s)
	if start < 0 {
		return CEF{}, false
	}
	s = s[start+len(cefPrefix):]
	var hdr [7]string
	for i := 0; i < 7; i++ {
		end := unescapedIndex(s, '|')
		if end < 0 {
			if i == 6 { // extension may be absent
				hdr[i] = s
				s = ""
				break
			}
			return CEF{}, false
		}
		hdr[i] = unescapeCEF(s[:end], false)
		s = s[end+1:]
	}
	c := CEF{Version: hdr[0], Vendor: hdr[1], Product: hdr[2], DeviceVersion: hdr[3],
		SignatureID: hdr[4], Name: hdr[5], Severity: hdr[6]}
	c.Ext = parseCEFExt(s)
	return c, true
}

// unescapedIndex finds the first c in s not preceded by an odd run of '\'.
func unescapedIndex(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip the escaped byte
			continue
		}
		if s[i] == c {
			return i
		}
	}
	return -1
}

// parseCEFExt splits the extension by ` key=` lookahead. A key is
// `[A-Za-z0-9_.-]+` immediately followed by '=' and preceded by the start or a
// space; `\=` inside a value is not a key boundary.
func parseCEFExt(s string) map[string]string {
	s = strings.TrimLeft(s, " ")
	out := make(map[string]string, 16)
	for len(s) > 0 {
		eq := unescapedIndex(s, '=')
		if eq <= 0 {
			break
		}
		key := s[:eq]
		if !isCEFKey(key) {
			break
		}
		rest := s[eq+1:]
		// Value ends at the next " key=" boundary.
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] != ' ' {
				continue
			}
			j := i + 1
			for j < len(rest) && isCEFKeyByte(rest[j]) {
				j++
			}
			if j > i+1 && j < len(rest) && rest[j] == '=' {
				end = i
				break
			}
		}
		out[strings.ToLower(key)] = unescapeCEF(rest[:end], true)
		if end >= len(rest) {
			break
		}
		s = rest[end+1:]
	}
	return out
}

func isCEFKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		if !isCEFKeyByte(k[i]) {
			return false
		}
	}
	return true
}

func isCEFKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// unescapeCEF resolves the CEF escapes. Header fields unescape `\|` and `\\`;
// extension values also `\=`, `\n`, `\r`. Returns the input unchanged (no
// allocation) when it holds no backslash.
func unescapeCEF(s string, ext bool) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case '\\', '|':
			b.WriteByte(s[i])
		case '=':
			if ext {
				b.WriteByte('=')
			} else {
				b.WriteString(`\=`)
			}
		case 'n':
			if ext {
				b.WriteByte('\n')
			} else {
				b.WriteString(`\n`)
			}
		case 'r':
			if ext {
				b.WriteByte('\r')
			} else {
				b.WriteString(`\r`)
			}
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
