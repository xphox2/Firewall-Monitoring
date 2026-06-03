"""AUDIT-069: add role/aria-modal/aria-labelledby to static modal markup so
modals are accessible at parse time, not only after tagStaticModals() runs.

Scope: admin.html + device-detail.html (the audit's cited files; all use the
`<div class="modal" id="X">` shape). For each modal:
  * add role="dialog" aria-modal="true" aria-labelledby="<title-id>" to the div
    (skipped if it already has role=).
  * <title-id> is the id of the modal's first <h2>/<h3>. If that heading has no
    id, inject id="<modal-id>-title" (the same convention tagStaticModals uses).

Mirrors cmd/api/static/js/admin-common.js tagStaticModals(). Run with --apply.
"""
import re
import sys

FILES = ["web/admin/admin.html", "web/admin/device-detail.html"]
MODAL = re.compile(r'^(\s*)<div class="modal" id="([^"]+)">\s*$')
HEAD_OPEN = re.compile(r"<h[23]\b")
HEAD_ID = re.compile(r'<h[23]\b[^>]*\bid="([^"]+)"')
LOOK = 10


def main():
    apply = "--apply" in sys.argv[1:]
    total = 0
    for path in FILES:
        with open(path, "r", encoding="utf-8") as fh:
            lines = open(path, encoding="utf-8").read().split("\n")
        changes = []
        i = 0
        while i < len(lines):
            m = MODAL.match(lines[i])
            if not m:
                i += 1
                continue
            indent, mid = m.group(1), m.group(2)
            if "role=" in lines[i]:
                i += 1
                continue
            # find the first h2/h3 heading within LOOK lines
            title_id = None
            for j in range(i + 1, min(i + 1 + LOOK, len(lines))):
                if HEAD_OPEN.search(lines[j]):
                    idm = HEAD_ID.search(lines[j])
                    if idm:
                        title_id = idm.group(1)
                    else:
                        title_id = mid + "-title"
                        lines[j] = re.sub(r"(<h[23])\b", r'\1 id="%s"' % title_id, lines[j], count=1)
                    break
            if not title_id:
                title_id = mid + "-title"  # no heading found; still label by convention
            lines[i] = '%s<div class="modal" id="%s" role="dialog" aria-modal="true" aria-labelledby="%s">' % (indent, mid, title_id)
            changes.append((i + 1, mid, title_id))
            i += 1
        print("%s: %d modal(s)" % (path, len(changes)))
        for ln, mid, tid in changes:
            print("    line %d: #%s -> aria-labelledby=%r" % (ln, mid, tid))
        total += len(changes)
        if apply and changes:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(lines))
    print("TOTAL modals tagged: %d (apply=%s)" % (total, apply))


if __name__ == "__main__":
    main()
