#!/usr/bin/env python3
"""
fix_query_get.py
================
Replaces all deprecated SQLAlchemy .query.get() calls with the
modern db.session.get() syntax required by SQLAlchemy 2.x.

WHY THIS MATTERS:
  Old:  Model.query.get(id)          ← deprecated, returns None silently
  New:  db.session.get(Model, id)    ← explicit, raises proper errors

Run from your project root:
  python3 scripts/fix_query_get.py
"""

import re
import sys
from pathlib import Path

# ── Models to fix ────────────────────────────────────────────
MODELS = ['EmailScan', 'Alert', 'User', 'TrainingRecord']

# ── Build replacement patterns ────────────────────────────────
def build_replacements(models):
    patterns = []
    for model in models:
        pattern     = rf'{model}\.query\.get\(([^)]+)\)'
        replacement = rf'db.session.get({model}, \1)'
        patterns.append((pattern, replacement))
    return patterns

# ── Fix a single file ─────────────────────────────────────────
def fix_file(fpath, patterns):
    content = fpath.read_text()
    original = content
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    if content != original:
        fpath.write_text(content)
        changed = sum(
            1 for a, b in zip(original.splitlines(), content.splitlines()) if a != b
        )
        print(f"  ✅ Fixed {fpath.relative_to(Path.cwd())} — {changed} line(s) changed")
        return True
    else:
        print(f"  ✓  No changes needed: {fpath.relative_to(Path.cwd())}")
        return False

# ── Main ──────────────────────────────────────────────────────
def main():
    root = Path(__file__).parent.parent   # project root
    routes_dir = root / 'backend' / 'app' / 'routes'

    if not routes_dir.exists():
        print(f"ERROR: routes dir not found at {routes_dir}")
        sys.exit(1)

    patterns = build_replacements(MODELS)
    py_files = list(routes_dir.glob('*.py'))

    print(f"\n🔍 Scanning {len(py_files)} route files in {routes_dir}\n")

    fixed_count = 0
    for fpath in sorted(py_files):
        if fix_file(fpath, patterns):
            fixed_count += 1

    print(f"\n{'✅ Done' if fixed_count else '✓  Nothing to change'} — {fixed_count} file(s) updated")
    if fixed_count:
        print("\n⚠  Restart Flask server to apply changes:")
        print("   Ctrl+C → python3 run.py\n")

if __name__ == '__main__':
    main()
