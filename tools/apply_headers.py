import re, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXTS = {".py": "#", ".rs": "//"}
SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "dist", "build", ".mypy_cache", ".ruff_cache", ".pytest_cache"}

TOKENS = [
    ("BIP143", re.compile(r"\bbip[-_ ]?143\b|sighash[_-]?bip143|bip143_sig_hash", re.I)),
    ("BIP141", re.compile(r"\bsegwit\b|\bwitness\b|\bp2wpkh\b|\bp2wsh\b", re.I)),
    ("BIP173", re.compile(r"\bbech32\b", re.I)),
    ("BIP39",  re.compile(r"\bmnemonic\b", re.I)),
    ("LWMA-Zawy", re.compile(r"\blwma\b|\bzawy\b", re.I)),
    ("CompactSize", re.compile(r"\bcompactsize\b|\bvarint\b", re.I)),
    ("Merkle", re.compile(r"\bmerkle\b", re.I)),
    ("libsecp256k1", re.compile(r"\bsecp256k1\b", re.I)),
    ("LowS-Policy", re.compile(r"\blow[_-]?s\b|der[_-]?low[_-]?s", re.I)),
]

def detect_tokens(text: str):
    found = []
    for name, rx in TOKENS:
        if rx.search(text):
            found.append(name)
    return found

def make_header(prefix: str, owner: str, year: str, refs: list[str], project: str):
    ref_line = f"{prefix} Refs: " + ("; ".join(refs) if refs else "see REFERENCES.md")
    return "\n".join([
        f"{prefix} SPDX-License-Identifier: MIT",
        f"{prefix} Copyright (c) {year} {owner}",
        f"{prefix} Part of {project} — see LICENSE and TRADEMARKS.md",
        ref_line,
        "",
    ])

def has_spdx(text: str):
    return re.search(r"SPDX-License-Identifier", text) is not None

def insert_header(path: Path, owner: str, year: str, project: str, dry: bool):
    ext = path.suffix
    prefix = EXTS.get(ext)
    if not prefix:
        return False, "skip-ext"

    data = path.read_text(encoding="utf-8", errors="replace")

    if has_spdx(data):
        return False, "already"

    refs = detect_tokens(data)
    header = make_header(prefix, owner, year, refs, project)

    out = data
    if ext == ".py" and data.startswith("#!"):
        lines = data.splitlines(True)
        shebang = lines[0]
        rest = "".join(lines[1:])
        out = shebang + header + rest
    else:
        out = header + data

    if not dry:
        path.write_text(out, encoding="utf-8")
    return True, ("added:" + ";".join(refs))

def should_skip(p: Path):
    parts = set(p.parts)
    return bool(SKIP_DIRS & parts)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--year", default="2025")
    ap.add_argument("--owner", default="Tsar Studio")
    ap.add_argument("--project", default="TsarChain")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()

    root = Path(args.root)
    changed = 0
    for p in root.rglob("*"):
        if p.is_dir() or should_skip(p): 
            continue
        if p.suffix not in EXTS:
            continue
        ok, why = insert_header(p, args.owner, args.year, args.project, args.dry_run)
        if ok:
            changed += 1
            print(f"[+] {p.relative_to(root)}  ({why})")
        elif why == "already":
            pass
        else:
            pass

    print(f"\nDone. {'(dry-run) ' if args.dry_run else ''}Headers added to {changed} file(s).")

if __name__ == "__main__":
    main()
