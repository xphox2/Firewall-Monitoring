package configdiff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Parser limits. These bound a pathological or hostile document; a real
// OPNsense config is ~60 KB and yields well under 200 objects.
const (
	maxOPNObjects        = 20000
	maxOPNAttrsPerObject = 2000
	maxOPNDepth          = 64
)

// keyFieldsByVendor maps a vendor to the child elements that carry an object's
// STABLE, operator-assigned identity, for the containers whose surrogate key
// CHURNS.
//
// Keyed per vendor rather than shared: stripping the document root puts
// OPNsense's legacy <filter><rule> and pfSense's rules at the same Kind, so one
// shared table would silently apply pfSense's {"tracker"} entry to OPNsense —
// and an OPNsense box migrated from pfSense can still carry <tracker> in its
// legacy rules, which would flip their keying and defeat the deliberate
// remove+add semantics documented on opnsenseKeyFields.
var keyFieldsByVendor = map[string]map[string][]string{
	"opnsense": opnsenseKeyFields,
	"pfsense":  pfsenseKeyFields,
}

// opnsenseKeyFields covers the containers whose uuid is known to churn.
//
// WHY this table exists: OPNsense reassigns every Swanctl uuid when a tunnel is
// deleted and recreated — verified against two consecutive production revisions
// where 52 raw lines differed and the residual after stripping uuids and
// timestamps was ZERO. Keying those objects on uuid reports an entire tunnel as
// removed+added for a semantically identical config.
//
// The LEGACY <filter><rule> is deliberately absent: its uuid is stable across
// in-place edits, so keying on uuid makes an edit diff as "modified" (what we
// want) and only churns on a genuine delete+recreate, where remove+add is the
// truthful answer. The PLUGIN OPNsense.Firewall.Filter rules are the ones our own
// IPsec provisioner writes, and those ARE regenerated with fresh uuids on every
// apply with byte-identical content — hence the entry.
//
// Values are JOINED, not alternatives: the provisioner sets the SAME description
// on every child of one tunnel (verified: four children all "fwm-t12"), so
// description alone is not unique for `child`.
//
// This is NOT a parsing whitelist — shape detection is fully generic, and an
// unlisted container parses correctly using its uuid.
var opnsenseKeyFields = map[string][]string{
	"OPNsense.Swanctl.Connections.Connection":   {"description"},
	"OPNsense.Swanctl.locals.local":             {"description", "round", "auth"},
	"OPNsense.Swanctl.remotes.remote":           {"description", "round", "auth"},
	"OPNsense.Swanctl.children.child":           {"description", "local_ts", "remote_ts"},
	"OPNsense.IPsec.preSharedKeys.preSharedKey": {"ident", "remote_ident"},
	"OPNsense.Firewall.Filter.rules.rule":       {"description", "sequence"},
	"system.user":                               {"name"},
	"system.group":                              {"name"},
}

// pfsenseKeyFields: pfSense's filter rules carry no uuid attribute — their
// stable identity is <tracker>. Without this the rules fall through to ordinal
// keying, and one mid-list insertion reads as N "modified" rules plus one add.
//
// UNVERIFIED against a real device. <tracker> has existed since pfSense 2.2, but
// rules surviving an old-version import may lack it; those degrade to the
// ordinal path. Confirm tracker-count == rule-count on a real corpus before
// trusting this.
var pfsenseKeyFields = map[string][]string{
	"filter.rule":  {"tracker"},
	"system.user":  {"name"},
	"system.group": {"name"},
}

var opnRefUUIDRegex = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// opnNode is a minimal DOM: enough to classify shape and flatten values, and
// nothing more. Comments, processing instructions and directives are discarded.
type opnNode struct {
	name  string
	attrs map[string]string
	text  string
	kids  []*opnNode
}

func (n *opnNode) isLeaf() bool { return len(n.kids) == 0 }

// ParseObjects parses an OPNsense/pfSense config.xml into vendor-neutral
// ConfigObjects so the diff can be rendered per-object instead of as a raw line
// delta.
//
// Deliberately TOLERANT, mirroring the FortiOS parser: it NEVER returns a
// non-nil error. Returning one makes DiffObjects report ok=false, which drops
// the vendor back to a line-only diff with no severity — the precise failure
// this parser exists to remove. A truncated or malformed document yields
// whatever objects were recoverable.
func (n opnsenseNormalizer) ParseObjects(raw []byte) ([]ConfigObject, error) {
	root := parseOPNsenseTree(raw)
	if root == nil {
		return nil, nil
	}

	p := &opnWalker{
		keyFields: keyFieldsByVendor[n.vendor],
		used:      make(map[string]bool),
		pathCount: make(map[string]int),
		byUUID:    make(map[string]string),
	}
	p.walk(root, "", 0)
	p.resolveRefs()
	return p.out, nil
}

// parseOPNsenseTree decodes the document into an opnNode tree, returning the
// root's content holder. Any decode error ends the walk and returns what was
// collected so far rather than failing the whole diff.
func parseOPNsenseTree(raw []byte) *opnNode {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	// Tolerate an unescaped '&' typed into an operator description rather than
	// aborting the document.
	dec.Strict = false
	// A non-UTF-8 encoding= declaration would otherwise abort the ENTIRE parse;
	// passing bytes through degrades to mojibake in one field instead.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }

	root := &opnNode{name: "#document"}
	stack := []*opnNode{root}
	objects := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			break // io.EOF or a syntax error: keep whatever we have
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > maxOPNDepth || objects > maxOPNObjects {
				return root
			}
			objects++
			node := &opnNode{name: t.Name.Local}
			if len(t.Attr) > 0 {
				node.attrs = make(map[string]string, len(t.Attr))
				for _, a := range t.Attr {
					node.attrs[a.Name.Local] = a.Value
				}
			}
			parent := stack[len(stack)-1]
			parent.kids = append(parent.kids, node)
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				cur := stack[len(stack)-1]
				if s := strings.TrimSpace(string(t)); s != "" {
					cur.text += s
				}
			}
		}
	}

	// The document root (<opnsense> / <pfsense>) is stripped from every Kind, so
	// return it rather than the synthetic holder.
	if len(root.kids) == 1 {
		return root.kids[0]
	}
	return root
}

type opnWalker struct {
	keyFields map[string][]string
	out       []ConfigObject
	used      map[string]bool
	pathCount map[string]int // base Path -> objects emitted sharing it (AUDIT-264)
	byUUID    map[string]string
}

// walk applies the shape rules to one container node.
//
// Four rules, evaluated per node, with no section whitelist:
//
//  1. Keyed list — the node has >=2 non-leaf children sharing a name, OR any
//     child carries a uuid. Each such child becomes an object. The uuid
//     tie-breaker is what lets a SINGLE-entry list still classify correctly.
//  2. Singleton — the node has >=1 leaf child. Rules 1 and 2 are NOT exclusive:
//     <system> holds scalars AND repeated <user>/<group>.
//  3. Named map — the node has no leaf children of its own and its children are
//     uniquely-named containers. Each child becomes an object keyed by its
//     element name (interfaces/wan).
//  4. Always recurse into any container whose subtree holds a keyed list,
//     whichever rule fired above.
//
// Rule 4 is what stops rules 2 and 3 from flattening a whole subtree and
// swallowing nested keyed lists — without it OPNsense.Firewall.Filter collapses
// eight firewall rules into one object with colliding attribute keys, silently
// hiding real changes behind last-wins.
func (p *opnWalker) walk(n *opnNode, path string, depth int) {
	if depth > maxOPNDepth || len(n.kids) == 0 || len(p.out) > maxOPNObjects {
		return
	}

	dupNames := map[string]int{}
	for _, c := range n.kids {
		if !c.isLeaf() {
			dupNames[c.name]++
		}
	}

	var keyed, leaves, containers []*opnNode
	for _, c := range n.kids {
		switch {
		case !c.isLeaf() && (c.attrs["uuid"] != "" || dupNames[c.name] > 1):
			keyed = append(keyed, c)
		case c.isLeaf():
			leaves = append(leaves, c)
		default:
			containers = append(containers, c)
		}
	}

	// Rule 1 — keyed list.
	for i, c := range keyed {
		kind := joinKind(path, c.name)
		p.emit(kind, p.nameFor(kind, c, i), c)
	}

	// Rule 4 — only a PURE-LEAF container may be flattened into its parent;
	// everything deeper is recursed so it can own its objects.
	//
	// Both halves of that test are load-bearing. Without the keyed-list check,
	// OPNsense.Firewall.Filter collapses eight firewall rules into one object with
	// colliding attribute keys, silently hiding real changes behind last-wins.
	// Without the depth check, an EMPTY plugin container (<Gateways/>, <radvd/>)
	// parses as a leaf, which makes its parent qualify as a singleton and drags
	// every sibling subtree in with it — the whole <OPNsense> plugin tree ends up
	// flattened onto one object.
	var recurse, valueGroups []*opnNode
	for _, c := range containers {
		if isPureLeafGroup(c) && !subtreeHasKeyedList(c) {
			valueGroups = append(valueGroups, c)
		} else {
			recurse = append(recurse, c)
		}
	}

	switch {
	case len(leaves) > 0 && path != "":
		// Rule 2 — singleton. Attrs are this node's OWN leaves plus its pure-leaf
		// value groups; never a child emitted as an object or one being recursed.
		//
		// Emitted at (parentPath, ownName) — the SAME coordinates rule 3 uses —
		// so a container's Path never depends on its own shape. It otherwise
		// flips: OPNsense.Firewall.Filter while it holds rules, then
		// OPNsense.Firewall/Filter once emptied, which reads as one object
		// removed and a different one added when nothing moved.
		attrs := make(map[string]string)
		collectLeaves(leaves, "", attrs)
		for _, c := range valueGroups {
			flattenNode(c, c.name+".", attrs)
		}
		p.append(singletonObject(path, attrs))

	case len(leaves) == 0 && len(valueGroups) > 0 && path != "" && uniqueNames(valueGroups):
		// Rule 3 — named map.
		for _, c := range valueGroups {
			attrs := make(map[string]string)
			flattenNode(c, "", attrs)
			p.append(ConfigObject{Kind: path, Name: c.name, Path: path + "/" + c.name, Attrs: attrs})
		}

	default:
		// Non-unique value groups with no leaves: recurse rather than lose them.
		recurse = append(recurse, valueGroups...)
	}

	for _, c := range recurse {
		p.walk(c, joinKind(path, c.name), depth+1)
	}
}

// emit records one keyed-list object, flattening its whole subtree.
func (p *opnWalker) emit(kind, name string, c *opnNode) {
	attrs := make(map[string]string)
	flattenNode(c, "", attrs)
	obj := ConfigObject{Kind: kind, Name: name, Path: kind + "/" + name, Attrs: attrs}
	if u := c.attrs["uuid"]; u != "" {
		p.byUUID[u] = obj.Path
	}
	p.append(obj)
}

// append adds an object, guarding against a Path collision. Two objects sharing
// a Path would silently overwrite one another in indexObjects, making one of
// them invisible to the diff.
//
// Collisions are disambiguated by a PER-BASE-PATH occurrence counter — the Nth
// object sharing this base Path — NOT the global emission ordinal len(p.out)
// (AUDIT-264). DiffObjects keys strictly on Path, so a suffix derived from the
// global ordinal shifts whenever an UNRELATED object is inserted or removed
// earlier in the walk: the same logical object then gets a different synthetic
// Path between snapshots A and B and churns as a spurious remove+add. An
// occurrence counter keyed on the base Path is stable under such unrelated
// insertions — the 2nd colliding "kind/name" is always "kind/name#2" regardless
// of how many other objects preceded it. The inner loop advances the counter
// again in the (contrived) event the synthetic Path itself already exists.
func (p *opnWalker) append(o ConfigObject) {
	if p.used[o.Path] {
		base := o.Path
		for {
			p.pathCount[base]++
			o.Path = base + "#" + strconv.Itoa(p.pathCount[base]+1)
			if !p.used[o.Path] {
				break
			}
		}
	}
	p.used[o.Path] = true
	p.out = append(p.out, o)
}

// nameFor resolves a keyed-list child's identity: the vendor's key table first,
// then the uuid attribute, then an ordinal.
func (p *opnWalker) nameFor(kind string, c *opnNode, idx int) string {
	if fields, ok := p.keyFields[kind]; ok {
		parts := make([]string, 0, len(fields))
		any := false
		for _, f := range fields {
			v := childText(c, f)
			if v != "" {
				any = true
			}
			parts = append(parts, v)
		}
		if any {
			return strings.Join(parts, "|")
		}
	}
	if u := c.attrs["uuid"]; u != "" {
		return u
	}
	return "#" + strconv.Itoa(idx+1)
}

// resolveRefs rewrites attribute VALUES that are bare uuids into the resolved
// Path of the object they point at, so a recreate does not churn every
// cross-reference after the objects themselves resolved to stable names.
//
// A uuid with no matching object becomes "uuid-ref:<8 hex of its hash>" —
// CONTENT-derived, deliberately not a positional token. Two dangling refs must
// stay distinguishable (so a retarget is visible) while an unchanged dangling ref
// must not shift when an unrelated uuid is inserted earlier; an ordinal fails
// both at once.
//
// Values are split on ',' first: repeated leaves are joined with commas during
// flattening, so a multi-valued reference field would never match a
// whole-value-anchored uuid pattern and the churn would re-enter here.
func (p *opnWalker) resolveRefs() {
	for i := range p.out {
		for k, v := range p.out[i].Attrs {
			if !strings.Contains(v, "-") {
				continue
			}
			parts := strings.Split(v, ",")
			changed := false
			for j, part := range parts {
				t := strings.TrimSpace(part)
				if !opnRefUUIDRegex.MatchString(t) {
					continue
				}
				if path, ok := p.byUUID[t]; ok {
					parts[j] = "ref:" + path
				} else {
					sum := sha256.Sum256([]byte(t))
					parts[j] = "uuid-ref:" + hex.EncodeToString(sum[:])[:8]
				}
				changed = true
			}
			if changed {
				p.out[i].Attrs[k] = strings.Join(parts, ",")
			}
		}
	}
}

// subtreeHasKeyedList reports whether any descendant of n is a keyed-list member
// (carries a uuid, or is one of >=2 same-named container siblings).
func subtreeHasKeyedList(n *opnNode) bool {
	dupNames := map[string]int{}
	for _, c := range n.kids {
		if !c.isLeaf() {
			dupNames[c.name]++
		}
	}
	for _, c := range n.kids {
		if c.isLeaf() {
			continue
		}
		if c.attrs["uuid"] != "" || dupNames[c.name] > 1 {
			return true
		}
		if subtreeHasKeyedList(c) {
			return true
		}
	}
	return false
}

// flattenNode flattens a node's whole subtree into dotted attribute keys
// (destination.port=443), mirroring the FortiOS parser's nested-block prefixing.
func flattenNode(n *opnNode, prefix string, out map[string]string) {
	if len(out) > maxOPNAttrsPerObject {
		return
	}
	var leaves []*opnNode
	for _, c := range n.kids {
		for ak, av := range c.attrs {
			if ak == "uuid" {
				// A surrogate key carries no operator meaning; emitting it
				// guarantees a spurious delta on every recreate even when the
				// identity resolved correctly.
				continue
			}
			out[prefix+c.name+"@"+ak] = av
		}
		if c.isLeaf() {
			leaves = append(leaves, c)
			continue
		}
		flattenNode(c, prefix+c.name+".", out)
	}
	collectLeaves(leaves, prefix, out)
}

// collectLeaves writes leaf values, joining repeated keys with ','.
//
// Sorted before joining so a device-side reorder is not a change, and
// deterministic so the hash stays stable. An empty element becomes
// attrPresentValue, never "" — see that constant for why.
func collectLeaves(leaves []*opnNode, prefix string, out map[string]string) {
	multi := map[string][]string{}
	for _, c := range leaves {
		v := c.text
		if v == "" {
			v = attrPresentValue
		}
		multi[prefix+c.name] = append(multi[prefix+c.name], v)
	}
	for k, vals := range multi {
		if len(vals) == 1 {
			out[k] = vals[0]
			continue
		}
		sort.Strings(vals)
		out[k] = strings.Join(vals, ",")
	}
}

func childText(n *opnNode, name string) string {
	for _, c := range n.kids {
		if c.name == name {
			return c.text
		}
	}
	return ""
}

// singletonObject places a container's own attributes at (parentKind, ownName),
// matching the coordinates the named-map rule uses for the same container.
//
// A top-level section (no dot in its path) keeps the bare Kind with an empty
// Name: nothing above it can vary, so there is no shape to flip.
func singletonObject(path string, attrs map[string]string) ConfigObject {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return ConfigObject{Kind: path, Name: "", Path: path, Attrs: attrs}
	}
	parent, own := path[:i], path[i+1:]
	return ConfigObject{Kind: parent, Name: own, Path: parent + "/" + own, Attrs: attrs}
}

// isPureLeafGroup reports whether every child of n is a leaf — i.e. n is a
// one-level value group like <webgui><protocol>https</protocol></webgui>, safe to
// flatten into its parent as webgui.protocol.
func isPureLeafGroup(n *opnNode) bool {
	for _, c := range n.kids {
		if !c.isLeaf() {
			return false
		}
	}
	return true
}

func uniqueNames(nodes []*opnNode) bool {
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if seen[n.name] {
			return false
		}
		seen[n.name] = true
	}
	return true
}

// joinKind builds the dotted Kind path. Case is PRESERVED: "OPNsense.Swanctl…"
// is what appears in the file, in the OPNsense model definitions, and in the API
// paths the IPsec driver uses, so lowercasing it would stop the object view
// matching anything an operator can grep for. Note the quirk that the document
// root is lowercase <opnsense> while the plugin section is capitalised
// <OPNsense>; only the latter ever appears in a Kind.
func joinKind(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
