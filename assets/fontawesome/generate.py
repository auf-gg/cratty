#!/usr/bin/env python3
"""Собирает icons.tsv.gz из пакета Font Awesome Free.

    npm pack @fortawesome/fontawesome-free && tar -xzf fortawesome-*.tgz
    python3 generate.py package/metadata/icon-families.json

Берутся наборы Brands и Classic (Solid, Regular). Строка файла:
стиль, имя, ширина, высота, подпись, поисковые слова, контур — через табуляцию.
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
    print(f"{len(lines)} значков → {out}")


if __name__ == "__main__":
    main(sys.argv[1])
