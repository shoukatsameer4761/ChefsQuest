#!/usr/bin/env python3
"""Static tripwires for executable JavaScript build configuration and source."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "node_modules", ".next", "build", "Pods"}
SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx"}
TRIPWIRES = (
    re.compile(r"\bchild_process\b"),
    re.compile(r"\bexecSync\s*\("),
    re.compile(r"\bspawnSync\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bglobal\.i\s*="),
    re.compile(r"\b_0x[0-9a-f]{3,}\b", re.IGNORECASE),
    re.compile(r"readFileSync\s*\(\s*__filename"),
    re.compile(r"writeFileSync\s*\(\s*__filename"),
)


def scan() -> list[str]:
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue

        if path.name == "babel.config.js" and len(source) > 2048:
            findings.append(f"{relative}: unexpected Babel config size ({len(source)} bytes)")
        for pattern in TRIPWIRES:
            if pattern.search(source):
                findings.append(f"{relative}: matched static execution tripwire {pattern.pattern}")

    return findings


if __name__ == "__main__":
    results = scan()
    if results:
        print("Static security scan failed:", file=sys.stderr)
        print("\n".join(f"- {finding}" for finding in results), file=sys.stderr)
        sys.exit(1)
    print("Static security scan passed.")
