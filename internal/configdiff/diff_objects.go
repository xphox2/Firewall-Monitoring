package configdiff

import "sort"

// AttrDelta is a single changed attribute within an object. Old is empty when the
// attribute was added; New is empty when it was removed.
type AttrDelta struct {
	Key string `json:"key"`
	Old string `json:"old"`
	New string `json:"new"`
}

// ObjectChange describes how one config object differs between two snapshots,
// together with its security classification.
//
// Vendor is stamped by DiffObjects and selects the classifier rule set. It is
// additive JSON — the frontend ignores unknown keys.
type ObjectChange struct {
	Path   string      `json:"path"`
	Kind   string      `json:"kind"`
	Name   string      `json:"name"`
	Vendor string      `json:"vendor,omitempty"`
	Op     string      `json:"op"` // added | removed | modified
	Attrs  []AttrDelta `json:"attrs"`
	Risk   Risk        `json:"risk"`
}

// DiffObjects parses both configs into objects and returns the per-object changes
// classified by risk. ok is false when the vendor has no ObjectParser, in which
// case the caller should fall back to the line diff.
//
// Both inputs are prepared by parseInputFor before parsing, so volatile content
// (ENC blobs, IV drift, save timestamps) never appears as a change. That is the
// normalized form for most vendors; a vendor with its own ParseInput gets a
// preparation tuned for parsing rather than for hashing — see ParseInput.
func DiffObjects(vendor string, a, b []byte) (changes []ObjectChange, ok bool) {
	objsA, okA := ParseObjects(vendor, parseInputFor(vendor, a))
	objsB, okB := ParseObjects(vendor, parseInputFor(vendor, b))
	if !okA || !okB {
		return nil, false
	}

	ia := indexObjects(objsA)
	ib := indexObjects(objsB)

	for path, oa := range ia {
		ob, present := ib[path]
		if !present {
			changes = append(changes, classified(vendor, ObjectChange{
				Path: oa.Path, Kind: oa.Kind, Name: oa.Name, Op: "removed",
				Attrs: attrsAsSide(oa.Attrs, false),
			}))
			continue
		}
		if deltas := diffAttrs(oa.Attrs, ob.Attrs); len(deltas) > 0 {
			changes = append(changes, classified(vendor, ObjectChange{
				Path: oa.Path, Kind: oa.Kind, Name: oa.Name, Op: "modified",
				Attrs: deltas,
			}))
		}
	}
	for path, ob := range ib {
		if _, present := ia[path]; !present {
			changes = append(changes, classified(vendor, ObjectChange{
				Path: ob.Path, Kind: ob.Kind, Name: ob.Name, Op: "added",
				Attrs: attrsAsSide(ob.Attrs, true),
			}))
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, true
}

func indexObjects(objs []ConfigObject) map[string]ConfigObject {
	m := make(map[string]ConfigObject, len(objs))
	for _, o := range objs {
		m[o.Path] = o
	}
	return m
}

// diffAttrs returns the sorted attribute deltas between two attribute maps.
func diffAttrs(a, b map[string]string) []AttrDelta {
	var out []AttrDelta
	for k, av := range a {
		if bv, ok := b[k]; !ok {
			out = append(out, AttrDelta{Key: k, Old: av})
		} else if av != bv {
			out = append(out, AttrDelta{Key: k, Old: av, New: bv})
		}
	}
	for k, bv := range b {
		if _, ok := a[k]; !ok {
			out = append(out, AttrDelta{Key: k, New: bv})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// attrsAsSide renders a whole object's attributes as deltas for an added (new=true)
// or removed (new=false) object.
func attrsAsSide(attrs map[string]string, new bool) []AttrDelta {
	out := make([]AttrDelta, 0, len(attrs))
	for k, v := range attrs {
		if new {
			out = append(out, AttrDelta{Key: k, New: v})
		} else {
			out = append(out, AttrDelta{Key: k, Old: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// classified stamps the vendor and then classifies. The order matters:
// ClassifyChange dispatches on Vendor, so stamping after classification would
// silently route every change through the fallback rule set.
func classified(vendor string, c ObjectChange) ObjectChange {
	c.Vendor = vendor
	c.Risk = ClassifyChange(c)
	return c
}
