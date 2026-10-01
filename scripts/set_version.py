#!/usr/bin/env python3
"""Set one SDK version everywhere it is published.

Run from the repository root:
    make version VERSION=0.11.2

Updates the three SDK manifests and the landing page SDK note (English and
Chinese) by replacing only the version text, so formatting is kept and every
file still ends with a newline. Editing package.json by hand in an editor that
formats JSON on save can drop that final newline.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ('packages/agent-protocols/package.json', r'(?m)^(  "version": ")[^"]*(",)$'),
    ('crates/agent-protocols/Cargo.toml', r'(?m)^(version = ")[^"]*(")$'),
    ('python/agent-protocols/pyproject.toml', r'(?m)^(version = ")[^"]*(")$'),
    ('docs/index.html', r'(current draft sources \(v)[^)]*(\))'),
    ('docs/index.html', r'(当前草案源码（v)[^）]*(）)'),
]


def main() -> None:
    if len(sys.argv) != 2 or not re.fullmatch(r'\d+\.\d+\.\d+', sys.argv[1]):
        sys.exit('usage: set_version.py X.Y.Z')
    version = sys.argv[1]
    texts: dict[str, str] = {}
    for path, pattern in TARGETS:
        text = texts.get(path) or (ROOT / path).read_text()
        text, count = re.subn(pattern, rf'\g<1>{version}\g<2>', text)
        if count != 1:
            sys.exit(f'{path}: expected one version match for {pattern!r}, found {count}')
        texts[path] = text
    for path, text in texts.items():
        (ROOT / path).write_text(text if text.endswith('\n') else text + '\n')
        print(f'{path}: {version}')


if __name__ == '__main__':
    main()
