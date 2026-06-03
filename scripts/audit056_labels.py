"""AUDIT-056: add for="<id>" to non-wrapping <label> elements.

Conservative rules (no guessing):
  * Skip labels that already have a for= attribute.
  * Skip labels that WRAP their control (<input|<select|<textarea between
    <label ...> and </label>) — those have an implicit association already.
  * For a non-wrapping label, look at the lines AFTER its </label> for the
    next id-bearing <input|<select|<textarea. Stop at the next <label
    (that control belongs to the other label) — never associate across a
    label boundary. Only add for= when an id is actually found.

Prints every change so the diff can be reviewed.
"""
import re
import sys

FILES = [
    "web/admin/probes.html",
    "web/admin/sites.html",
    "web/admin/irc.html",
    "web/admin/probe-pending.html",
    "web/admin/admin.html",
]

LABEL_OPEN = re.compile(r"<label(?![^>]*\bfor=)\b")
CONTROL_ID = re.compile(r'<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"')
ANY_CONTROL = re.compile(r"<(?:input|select|textarea)\b")
WINDOW = 5

total = 0
for path in FILES:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    lines = text.split("\n")
    n = len(lines)
    changed = []
    for i in range(n):
        if not LABEL_OPEN.search(lines[i]):
            continue
        # Build the label's text from its <label until </label> (same or later line).
        start = lines[i].index("<label")
        combined = lines[i][start:]
        end_line = i
        while "</label>" not in combined and end_line < n - 1:
            end_line += 1
            combined += "\n" + lines[end_line]
        label_inner = combined.split("</label>")[0]
        if ANY_CONTROL.search(label_inner):
            continue  # wrapping label — implicit association
        # Look forward (after the label) for the next control with an id.
        target = None
        for f in range(end_line + 1, min(end_line + 1 + WINDOW, n)):
            if "<label" in lines[f]:
                break  # next label owns the next control
            m = CONTROL_ID.search(lines[f])
            if m:
                target = m.group(1)
                break
            if ANY_CONTROL.search(lines[f]):
                break  # a control with no id — don't guess
        if not target:
            continue
        new = LABEL_OPEN.sub('<label for="%s"' % target, lines[i], count=1)
        if new != lines[i]:
            lines[i] = new
            changed.append((i + 1, target))
    if changed:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines))
    print("%s: %d labels updated" % (path, len(changed)))
    for ln, tid in changed:
        print("    line %d -> for=%r" % (ln, tid))
    total += len(changed)

print("TOTAL: %d labels updated" % total)
