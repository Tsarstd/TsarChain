# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import ast, os, sys, re, subprocess
from importlib.metadata import packages_distributions

IGNORE_DIRS = {'.venv','venv','env','virtualenv','__pycache__','.git','.vscode','.idea','node_modules','dist','build','.mypy_cache'}
IGNORE_DIRS_TESTS = {'tests','test','examples','docs'}

# Mapping: top-level import name -> PyPI distribution name
MANUAL_MAP = {
    'sklearn': 'scikit-learn',
    'PIL': 'Pillow',
    'bs4': 'beautifulsoup4',
    'cv2': 'opencv-python',
    'yaml': 'PyYAML',
    'nacl': 'PyNaCl',
    'dateutil': 'python-dateutil',
    'googleapiclient': 'google-api-python-client',
    'grpc': 'grpcio',
    'Crypto': 'pycryptodome',
    'typing_extensions': 'typing-extensions',
}

def norm(s: str) -> str:
    return s.lower().replace('_','-')

def walk_py_files(root='.'):
    for r, dirs, files in os.walk(root):
        # drop ignored dirs
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and d not in IGNORE_DIRS_TESTS]
        for fn in files:
            if fn.endswith('.py'):
                yield os.path.join(r, fn)

def collect_top_level_modules():
    mods = set()
    for path in walk_py_files('.'):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=path)
        except UnicodeDecodeError:
            with open(path, 'r', encoding='latin-1', errors='ignore') as f:
                tree = ast.parse(f.read(), filename=path)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    mods.add(n.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module and not node.level:
                    mods.add(node.module.split('.')[0])
    return mods

def load_freeze_lines():
    freeze = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines()
    name_to_line = {}
    for line in freeze:
        if not line or line.startswith('#'):
            continue
        m_eq = re.match(r'^([A-Za-z0-9_.\-]+)==', line)
        m_at = re.match(r'^([A-Za-z0-9_.\-]+)\s*@\s*', line)
        key = None
        if m_eq:
            key = norm(m_eq.group(1))
        elif m_at:
            key = norm(m_at.group(1))
        if key:
            # first wins; prefer pinned if duplicates
            name_to_line.setdefault(key, line)
    return name_to_line

def modules_to_distributions(mods):
    dist_map = packages_distributions()  # module -> [dists]
    dists = set()
    misses = []
    for m in mods:
        m_norm = m
        if m in MANUAL_MAP:
            dists.add(norm(MANUAL_MAP[m]))
            continue

        candidates = dist_map.get(m, [])
        if candidates:
            for d in candidates:
                dists.add(norm(d))
            continue

        if m.lower() == 'google':
            for d in ('protobuf','google-api-python-client','google-auth','google-auth-oauthlib'):
                dists.add(norm(d))
            continue

        misses.append(m)
    return dists, misses

def main():
    mods = collect_top_level_modules()
    dists, misses = modules_to_distributions(mods)
    freeze_lines = load_freeze_lines()

    included = []
    for d in sorted(dists):
        line = freeze_lines.get(d)
        if line:
            included.append(line)

    with open('requirements.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(included) + ('\n' if included else ''))

    # diagnostics
    if misses:
        print("⚠️  Unresolved modules (no distribution mapping found):", ', '.join(sorted(set(misses))))
    extra = sorted(set(d for d in dists if d not in freeze_lines))
    if extra:
        print("ℹ️  Mapped dists not present in current env (install then freeze?):", ', '.join(extra))
    for line in included:
        print(f"✅ Included: {line}")

if __name__ == '__main__':
    main()
