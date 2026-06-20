package configdiff

import "strings"

// ParseObjects parses FortiOS config text into vendor-neutral ConfigObjects so
// the diff can be rendered per-object (e.g. "firewall.policy/12 modified:
// dstaddr LAN -> all") instead of as a raw line delta. It is deliberately
// tolerant: unrecognized lines are skipped rather than erroring, so a partial or
// slightly malformed backup still yields whatever objects it can.
//
// FortiOS structure:
//
//	config <a b c>            -> a section, kind "a.b.c"
//	  edit "<key>"            -> a table entry => one object (Name=key)
//	    set <k> <v>           -> attribute on the entry
//	    config <sub> ... end  -> nested block; its sets flatten into the entry
//	  next                    -> end of entry           with key prefix "<sub>."
//	  set <k> <v>             -> a direct set => the section is a singleton object
//	end
//
// DiffObjects runs this on the NORMALIZED config, so ENC blobs and other
// volatile values are already collapsed and never diff as changes. A `set`
// attaches to the nearest enclosing `edit`; nested `config` blocks above that
// edit contribute a dotted key prefix. With no enclosing edit, the set attaches
// to the innermost `config` section as a singleton object.
func (fortigateNormalizer) ParseObjects(raw []byte) ([]ConfigObject, error) {
	type frame struct {
		isEdit bool
		seg    string            // config frames: dotted tokens, e.g. "system.interface"
		name   string            // edit frames: the entry key
		attrs  map[string]string // edit / singleton object attrs
		object bool              // true once this frame owns an emitted object
	}

	var (
		stack []*frame
		out   []ConfigObject
	)

	// configKind joins the dotted segments of every open config frame.
	configKind := func() string {
		var segs []string
		for _, f := range stack {
			if !f.isEdit {
				segs = append(segs, f.seg)
			}
		}
		return strings.Join(segs, ".")
	}

	// setTarget returns the frame a `set` attaches to plus a dotted key prefix
	// for nested config blocks between the owner and the cursor.
	setTarget := func() (*frame, string) {
		ownerIdx := -1
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].isEdit {
				ownerIdx = i
				break
			}
		}
		if ownerIdx >= 0 {
			var segs []string
			for i := ownerIdx + 1; i < len(stack); i++ {
				if !stack[i].isEdit {
					segs = append(segs, stack[i].seg)
				}
			}
			prefix := ""
			if len(segs) > 0 {
				prefix = strings.Join(segs, ".") + "."
			}
			return stack[ownerIdx], prefix
		}
		for i := len(stack) - 1; i >= 0; i-- {
			if !stack[i].isEdit {
				return stack[i], ""
			}
		}
		return nil, ""
	}

	emit := func(f *frame, kind, name string) {
		path := kind
		if name != "" {
			path = kind + "/" + name
		}
		out = append(out, ConfigObject{Kind: kind, Name: name, Path: path, Attrs: f.attrs})
	}

	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "config "):
			stack = append(stack, &frame{seg: dottedSeg(line[len("config "):]), attrs: map[string]string{}})

		case strings.HasPrefix(line, "edit "):
			key := unquoteToken(strings.TrimSpace(line[len("edit "):]))
			stack = append(stack, &frame{isEdit: true, name: key, attrs: map[string]string{}})

		case line == "next":
			// Close the nearest edit, emitting it as an object.
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].isEdit {
					kind := configKind()
					emit(stack[i], kind, stack[i].name)
					stack = stack[:i]
					break
				}
			}

		case line == "end":
			// Close the innermost config frame, emitting a singleton object if it
			// received direct sets (table sections emit via their edits instead).
			for i := len(stack) - 1; i >= 0; i-- {
				if !stack[i].isEdit {
					if stack[i].object {
						emit(stack[i], configKind(), "")
					}
					stack = stack[:i]
					break
				}
			}

		case strings.HasPrefix(line, "set "), strings.HasPrefix(line, "unset "):
			owner, prefix := setTarget()
			if owner == nil {
				continue
			}
			key, val := parseSetLine(line)
			if key == "" {
				continue
			}
			owner.attrs[prefix+key] = val
			owner.object = true
		}
	}

	return out, nil
}

// dottedSeg turns the token list of a `config a b c` header into "a.b.c".
func dottedSeg(rest string) string {
	return strings.Join(strings.Fields(rest), ".")
}

// unquoteToken strips a single pair of surrounding double quotes from an edit key.
func unquoteToken(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseSetLine splits a `set <key> <value...>` or `unset <key>` line into its
// key and value. An `unset` is recorded with the sentinel "<unset>" so it diffs
// distinctly from an absent attribute.
func parseSetLine(line string) (key, val string) {
	if strings.HasPrefix(line, "unset ") {
		return strings.TrimSpace(line[len("unset "):]), "<unset>"
	}
	fields := strings.Fields(line[len("set "):])
	if len(fields) == 0 {
		return "", ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}
