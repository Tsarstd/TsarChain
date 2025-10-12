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
    # --- Secure Messaging / Transport primitives (auto refs) ---
    ("Signal-X3DH", re.compile(r"\bx3dh\b|signed[-_ ]?prekey|one[-_ ]?time[-_ ]?prekey|\b(?:opk|spk)\b", re.I)),
    ("Signal-DoubleRatchet", re.compile(r"\bdouble[-_ ]?ratchet\b|\bratchet[-_ ]?session\b|\bdh[-_ ]?ratchet\b", re.I)),
    ("RFC7748-X25519", re.compile(r"\bx25519\b|\bcurve25519\b|\brfc\s*7748\b", re.I)),
    ("RFC5869-HKDF", re.compile(r"\bhkdf\b|\brfc\s*5869\b", re.I)),
    ("NIST-800-38D-AES-GCM", re.compile(r"\baes[-_]?gcm\b|\bgcm\b|nist.*800[-_ ]?38[dD]\b", re.I)),
]

def detect_tokens(text: str):
    found = []
    for name, rx in TOKENS:
        if rx.search(text):
            found.append(name)
    return found

def _refs_line(prefix: str, refs: list[str]) -> str:
    return f"{prefix} Refs: " + ("; ".join(refs) if refs else "see REFERENCES.md")

def make_header(prefix: str, owner: str, year: str, refs: list[str], project: str):
    ref_line = _refs_line(prefix, refs)
    return "\n".join([
        f"{prefix} SPDX-License-Identifier: MIT",
        f"{prefix} Copyright (c) {year} {owner}",
        f"{prefix} Part of {project} — see LICENSE and TRADEMARKS.md",
        ref_line,
        "",
    ])

def has_spdx(text: str):
    return re.search(r"SPDX-License-Identifier", text) is not None

def _refresh_refs_in_text(data: str, prefix: str, refs: list[str]) -> tuple[str, bool]:
    refs_rx = re.compile(rf"^(?:{re.escape(prefix)}+\s*)Refs\s*:\s*.*$", flags=re.M | re.I)
    new_line = _refs_line(prefix, refs)
    if refs_rx.search(data):
        return refs_rx.sub(new_line, data, count=1), True

    partof_rx = re.compile(rf"^{re.escape(prefix)}\s*Part of .*?TRADEMARKS\.md\s*$", flags=re.M | re.I)
    m = partof_rx.search(data)
    if m:
        idx = m.end()
        before, after = data[:idx], data[idx:]
        insert = ("\n" if not before.endswith("\n") else "") + new_line + ("\n" if not after.startswith("\n") else "")
        return before + insert + after, True
    
    return data, False

def insert_header(path: Path, owner: str, year: str, project: str, dry: bool, refresh_refs: bool = False):
    ext = path.suffix
    prefix = EXTS.get(ext)
    if not prefix:
        return False, "skip-ext"

    data = path.read_text(encoding="utf-8", errors="replace")

    if has_spdx(data):
        refs = detect_tokens(data)
        new_data, changed = _refresh_refs_in_text(data, prefix, refs)
        if changed and not dry:
            path.write_text(new_data, encoding="utf-8")
        return changed, ("refreshed:" + ";".join(refs) if changed else "already")

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
    ap.add_argument("--refresh-refs", action="store_true", help="(Deprecated) Refs are always refreshed if SPDX header exists")
    args = ap.parse_args()

    root = Path(args.root)
    changed = 0
    for p in root.rglob("*"):
        if p.is_dir() or should_skip(p): 
            continue
        if p.suffix not in EXTS:
            continue
        ok, why = insert_header(p, args.owner, args.year, args.project, args.dry_run, args.refresh_refs)
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
