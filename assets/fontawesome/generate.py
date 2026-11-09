#!/usr/bin/env python3
"""Builds icons.tsv.gz from the Font Awesome Free package.

    npm pack @fortawesome/fontawesome-free && tar -xzf fortawesome-*.tgz
    python3 generate.py package/metadata/icon-families.json

The Brands and Classic (Solid, Regular) sets are used. File line:
style, name, width, height, label, search terms, outline — tab-separated.
"""

import gzip
import json
import sys
from pathlib import Path

STYLES = ("solid", "regular", "brands")


def clean(text):
    return " ".join(str(text).replace("\t", " ").split())


def main(source):
    families = json.loads(Path(source).read_text())
    lines = []
    for name, icon in sorted(families.items()):
        classic = icon.get("svgs", {}).get("classic", {})
        for style in STYLES:
            svg = classic.get(style)
            if not svg:
                continue
            _, _, width, height = svg["viewBox"]
            terms = " ".join(clean(term) for term in icon.get("search", {}).get("terms", []))
            lines.append(
                "\t".join(
                    [style, name, str(width), str(height), clean(icon.get("label", name)), terms, svg["path"]]
                )
            )
    out = Path(__file__).with_name("icons.tsv.gz")
    out.write_bytes(gzip.compress("\n".join(lines).encode(), 9, mtime=0))
    print(f"{len(lines)} icons → {out}")


if __name__ == "__main__":
    main(sys.argv[1])
