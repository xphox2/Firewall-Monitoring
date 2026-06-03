"""AUDIT-066/067: brighten a too-dark TEXT color to #8b949e.

Only touches foreground-text contexts, never decoration:
  * the `color:` CSS property (NOT `border-color`/`background-color`/etc. —
    excluded via a negative lookbehind for `-` or a word char before `color`).
    Works in .css files, inline <style> blocks, and inline style="" attributes,
    AND inside JS strings that build inline styles (`style="color:#hex"`).
  * Tailwind `text-[#hex]` utilities in HTML.

It never matches chart configs: in JS, hex values are ALWAYS quoted
(`color: '#484f58'`), and an unquoted `color:#hex` / `color: #hex` only ever
appears inside an inline-style string — so quoted chart colors are left alone.
Borders, backgrounds, and bg-[...]/border-[...] utilities are left alone.

Usage:
  python scripts/audit_brighten_color.py <#oldhex> [--apply]
Without --apply it only reports what it would change.
"""
import re
import sys

NEW = "#8b949e"
FILES = [
    "cmd/api/static/css/admin-shared.css",
    "cmd/api/static/css/admin-design-system.css",
    "cmd/api/static/css/styles.css",
    "cmd/api/static/css/tailwind.css",
    "web/admin/admin.html",
    "web/admin/device-detail.html",
    "web/admin/connection-detail.html",
    "web/admin/irc.html",
    "web/admin/sites.html",
    "web/admin/probes.html",
    "web/admin/probe-pending.html",
    "web/public/index.html",
    "cmd/api/static/js/admin-common.js",
    "cmd/api/static/js/admin-main.js",
    "cmd/api/static/js/admin-device-detail.js",
    "cmd/api/static/js/admin-connection-detail.js",
    "cmd/api/static/js/public-dashboard.js",
    "cmd/api/static/js/diagram-panels.js",
    "cmd/api/static/js/diagram-cytoscape.js",
]


def patterns(old):
    h = re.escape(old)
    # color: property (not *-color:), optional space, unquoted hex
    color_prop = re.compile(r"(?<![-\w])(color:\s*)" + h + r"(?![0-9a-fA-F])")
    # Tailwind text-[#hex]
    text_util = re.compile(r"(text-\[)" + h + r"(\])")
    return color_prop, text_util


def main():
    if len(sys.argv) < 2:
        print("usage: audit_brighten_color.py <#oldhex> [--apply]")
        sys.exit(2)
    old = sys.argv[1]
    apply = "--apply" in sys.argv[2:]
    color_prop, text_util = patterns(old)

    total = 0
    for path in FILES:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            continue
        lines = text.split("\n")
        hits = []
        for i, line in enumerate(lines):
            if color_prop.search(line) or text_util.search(line):
                hits.append(i + 1)
        if not hits:
            continue
        new_text = color_prop.sub(lambda m: m.group(1) + NEW, text)
        new_text = text_util.sub(lambda m: m.group(1) + NEW + m.group(2), new_text)
        print("%s: %d line(s)" % (path, len(hits)))
        for ln in hits:
            print("    line %d: %s" % (ln, lines[ln - 1].strip()[:110]))
        total += len(hits)
        if apply:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(new_text)
    print("TOTAL lines with %s text-context: %d  (apply=%s)" % (old, total, apply))


if __name__ == "__main__":
    main()
