"""

python scripts/depend_version.py (Automatically check the entire project)
python scripts/depend_version.py --python / -py (Python Only)
python scripts/depend_version.py --rust / -rs (Rust Only)
python scripts/depend_version.py --backend / -be (Backend Web Only)
python scripts/depend_version.py --frontend / -fe (Frontend Web Only)
python scripts/depend_version.py --json (Output JSON format for CI/CD automation)
python scripts/depend_version.py --no-color (Disable ANSI color codes)

"""

import re
import os
import sys
import json
import tomllib
import argparse
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout.reconfigure(encoding='utf-8')

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

TARGETS = [
    {
        "id": "python",
        "name": "Python Dependencies",
        "icon": "🐍",
        "path": os.path.join(ROOT_DIR, "requirements.txt"),
        "eco": "pypi"
    },
    {
        "id": "rust",
        "name": "Rust Native Dependencies",
        "icon": "🦀",
        "path": os.path.join(ROOT_DIR, "tsarcore_native", "Cargo.toml"),
        "eco": "crates"
    },
    {
        "id": "backend",
        "name": "Backend Web Dependencies",
        "icon": "🟢",
        "path": os.path.join(ROOT_DIR, "src", "web", "Backend", "package.json"),
        "eco": "npm"
    },
    {
        "id": "frontend",
        "name": "Frontend Web Dependencies",
        "icon": "⚛️",
        "path": os.path.join(ROOT_DIR, "src", "web", "Frontend", "package.json"),
        "eco": "npm"
    }
]


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def disable_colors():
    Colors.GREEN = ""
    Colors.YELLOW = ""
    Colors.RED = ""
    Colors.CYAN = ""
    Colors.BLUE = ""
    Colors.MAGENTA = ""
    Colors.GRAY = ""
    Colors.BOLD = ""
    Colors.RESET = ""


def parse_semver(v_str):
    if not v_str:
        return ()
    clean = re.split(r'[-+]', str(v_str))[0]
    nums = re.findall(r'\d+', clean)
    return tuple(int(n) for n in nums)


def clean_version_string(v_str):
    if not v_str:
        return ""
    # Strip operators like ^, ~, >=, <=, ==, =, v
    v = re.sub(r'^[~^=><v]+', '', str(v_str).strip())
    return v.strip()


def fetch_pypi_info(pkg_name):
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    req = urllib.request.Request(url, headers={'User-Agent': 'TsarChain-DepChecker/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            latest = data.get('info', {}).get('version')
            releases = set(data.get('releases', {}).keys())
            return {"latest": latest, "versions": releases, "error": None}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"latest": None, "versions": set(), "error": "NOT_FOUND"}
        return {"latest": None, "versions": set(), "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"latest": None, "versions": set(), "error": str(e)}


def fetch_crates_info(pkg_name):
    url = f"https://crates.io/api/v1/crates/{pkg_name}"
    # Crates.io strictly requires User-Agent
    req = urllib.request.Request(url, headers={'User-Agent': 'TsarChain-DepChecker/1.0 (contact@tsarchain.com)'})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            c = data.get('crate', {})
            latest = c.get('max_stable_version') or c.get('max_version') or c.get('newest_version')
            versions = {v['num'] for v in data.get('versions', [])}
            return {"latest": latest, "versions": versions, "error": None}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"latest": None, "versions": set(), "error": "NOT_FOUND"}
        return {"latest": None, "versions": set(), "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"latest": None, "versions": set(), "error": str(e)}


def fetch_npm_info(pkg_name):
    quoted = urllib.parse.quote(pkg_name, safe='')
    url = f"https://registry.npmjs.org/{quoted}"
    req = urllib.request.Request(url, headers={'User-Agent': 'TsarChain-DepChecker/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            latest = data.get('dist-tags', {}).get('latest')
            versions = set(data.get('versions', {}).keys())
            return {"latest": latest, "versions": versions, "error": None}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"latest": None, "versions": set(), "error": "NOT_FOUND"}
        return {"latest": None, "versions": set(), "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"latest": None, "versions": set(), "error": str(e)}


def fetch_registry_info(eco, pkg_name):
    if eco == "pypi":
        return fetch_pypi_info(pkg_name)
    elif eco == "crates":
        return fetch_crates_info(pkg_name)
    elif eco == "npm":
        return fetch_npm_info(pkg_name)
    return {"latest": None, "versions": set(), "error": "UNKNOWN_ECOSYSTEM"}


def extract_python_deps(file_path):
    deps = []
    if not os.path.exists(file_path):
        return deps
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '==' in line:
                pkg, ver = line.split('==', 1)
                deps.append({
                    "display_name": pkg.strip(),
                    "query_name": pkg.strip(),
                    "raw_version": ver.strip(),
                    "clean_version": ver.strip(),
                    "kind": "dep",
                    "status_type": "check"
                })
            elif any(op in line for op in ['>=', '<=', '>', '<', '~=']):
                m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([><=~]+)\s*(.+)$', line)
                if m:
                    deps.append({
                        "display_name": m.group(1),
                        "query_name": m.group(1),
                        "raw_version": f"{m.group(2)}{m.group(3)}",
                        "clean_version": clean_version_string(m.group(3)),
                        "kind": "dep",
                        "status_type": "check"
                    })
                else:
                    deps.append({
                        "display_name": line,
                        "query_name": line,
                        "raw_version": line,
                        "clean_version": "",
                        "kind": "dep",
                        "status_type": "skipped"
                    })
            else:
                deps.append({
                    "display_name": line,
                    "query_name": line,
                    "raw_version": "unpinned",
                    "clean_version": "",
                    "kind": "dep",
                    "status_type": "check"
                })
    return deps


def extract_cargo_deps(file_path):
    deps = []
    if not os.path.exists(file_path):
        return deps

    with open(file_path, 'rb') as f:
        data = tomllib.load(f)

    sections = [
        ("dependencies", "dep"),
        ("dev-dependencies", "devDep"),
        ("build-dependencies", "buildDep")
    ]

    for section, kind in sections:
        if section in data and isinstance(data[section], dict):
            for pkg, val in data[section].items():
                if isinstance(val, str):
                    deps.append({
                        "display_name": pkg,
                        "query_name": pkg,
                        "raw_version": val,
                        "clean_version": clean_version_string(val),
                        "kind": kind,
                        "status_type": "check"
                    })
                elif isinstance(val, dict):
                    if 'path' in val or 'git' in val or val.get('workspace'):
                        dep_type = "workspace" if val.get('workspace') else "local/git"
                        deps.append({
                            "display_name": pkg,
                            "query_name": pkg,
                            "raw_version": str(val.get('path') or val.get('git') or 'workspace'),
                            "clean_version": "",
                            "kind": kind,
                            "status_type": dep_type
                        })
                    elif 'version' in val:
                        deps.append({
                            "display_name": pkg,
                            "query_name": pkg,
                            "raw_version": val['version'],
                            "clean_version": clean_version_string(val['version']),
                            "kind": kind,
                            "status_type": "check"
                        })
    return deps


def extract_npm_deps(file_path):
    deps = []
    if not os.path.exists(file_path):
        return deps
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    sections = [
        ("dependencies", "dep"),
        ("devDependencies", "devDep")
    ]

    for section, kind in sections:
        if section in data and isinstance(data[section], dict):
            for pkg, val in data[section].items():
                val_str = str(val).strip()
                if any(val_str.startswith(p) for p in ["file:", "git:", "http:", "https:", "link:"]):
                    deps.append({
                        "display_name": pkg,
                        "query_name": pkg,
                        "raw_version": val_str,
                        "clean_version": "",
                        "kind": kind,
                        "status_type": "local/git"
                    })
                elif val_str.startswith("npm:"):
                    m = re.match(r'^npm:([@a-zA-Z0-9_\-\./]+)@(.+)$', val_str)
                    if m:
                        real_pkg, ver = m.group(1), m.group(2)
                        deps.append({
                            "display_name": f"{pkg} ({real_pkg})",
                            "query_name": real_pkg,
                            "raw_version": ver,
                            "clean_version": clean_version_string(ver),
                            "kind": kind,
                            "status_type": "check"
                        })
                    else:
                        deps.append({
                            "display_name": pkg,
                            "query_name": pkg,
                            "raw_version": val_str,
                            "clean_version": "",
                            "kind": kind,
                            "status_type": "skipped"
                        })
                else:
                    deps.append({
                        "display_name": pkg,
                        "query_name": pkg,
                        "raw_version": val_str,
                        "clean_version": clean_version_string(val_str),
                        "kind": kind,
                        "status_type": "check"
                    })
    return deps


def extract_target_deps(target_info):
    eco = target_info["eco"]
    path = target_info["path"]
    if eco == "pypi":
        return extract_python_deps(path)
    elif eco == "crates":
        return extract_cargo_deps(path)
    elif eco == "npm":
        return extract_npm_deps(path)
    return []


def evaluate_dependency(item, reg_info):
    if item["status_type"] in ["local/git", "workspace"]:
        return {
            "status": "LOCAL/GIT" if item["status_type"] == "local/git" else "WORKSPACE",
            "badge": f"{Colors.GRAY}⚙️ LOCAL/GIT{Colors.RESET}",
            "latest": "N/A",
            "code": "LOCAL"
        }
    
    if item["status_type"] == "skipped":
        return {
            "status": "SKIPPED",
            "badge": f"{Colors.GRAY}⏩ SKIPPED{Colors.RESET}",
            "latest": "N/A",
            "code": "SKIP"
        }

    err = reg_info.get("error")
    if err == "NOT_FOUND":
        return {
            "status": "PKG NOT FOUND",
            "badge": f"{Colors.RED}🚫 NOT FOUND{Colors.RESET}",
            "latest": "N/A",
            "code": "NOT_FOUND"
        }
    elif err:
        return {
            "status": f"ERROR ({err})",
            "badge": f"{Colors.RED}❌ ERROR{Colors.RESET}",
            "latest": "N/A",
            "code": "ERROR"
        }

    latest = reg_info.get("latest")
    versions = reg_info.get("versions", set())
    clean_v = item["clean_version"]

    if not clean_v or not latest:
        return {
            "status": "UNKNOWN",
            "badge": f"{Colors.YELLOW}❓ UNKNOWN{Colors.RESET}",
            "latest": latest or "N/A",
            "code": "UNKNOWN"
        }

    ver_tuple = parse_semver(clean_v)
    latest_tuple = parse_semver(latest)

    # Version check logic
    version_exists = clean_v in versions or any(v.startswith(clean_v + '.') for v in versions)

    if ver_tuple >= latest_tuple and latest_tuple != ():
        return {
            "status": "LATEST",
            "badge": f"{Colors.GREEN}✅ LATEST{Colors.RESET}",
            "latest": latest,
            "code": "LATEST"
        }
    elif version_exists or ver_tuple != ():
        return {
            "status": f"UPDATE AVAILABLE (-> {latest})",
            "badge": f"{Colors.YELLOW}⚠️ UPDATE AVAILABLE{Colors.RESET}",
            "latest": latest,
            "code": "UPDATE"
        }
    else:
        return {
            "status": f"VERSION NOT FOUND (Latest: {latest})",
            "badge": f"{Colors.RED}❌ VER NOT FOUND{Colors.RESET}",
            "latest": latest,
            "code": "VER_NOT_FOUND"
        }

def process_target(target, workers=10):
    rel_path = os.path.relpath(target["path"], ROOT_DIR)
    if not os.path.exists(target["path"]):
        return {
            "target": target,
            "rel_path": rel_path,
            "exists": False,
            "results": [],
            "stats": {"total": 0, "latest": 0, "update": 0, "not_found": 0, "other": 0}
        }

    raw_deps = extract_target_deps(target)
    
    # Query registry in parallel
    check_items = [d for d in raw_deps if d["status_type"] == "check"]
    query_names = [*{d["query_name"] for d in check_items}]

    reg_cache = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_name = {executor.submit(fetch_registry_info, target["eco"], qn): qn for qn in query_names}
        for future in future_to_name:
            qn = future_to_name[future]
            try:
                reg_cache[qn] = future.result()
            except Exception as e:
                reg_cache[qn] = {"latest": None, "versions": set(), "error": str(e)}

    results = []
    stats = {"total": len(raw_deps), "latest": 0, "update": 0, "not_found": 0, "other": 0}

    for item in raw_deps:
        reg_info = reg_cache.get(item["query_name"], {})
        eval_res = evaluate_dependency(item, reg_info)
        
        c_code = eval_res["code"]
        if c_code == "LATEST":
            stats["latest"] += 1
        elif c_code == "UPDATE":
            stats["update"] += 1
        elif c_code in ["NOT_FOUND", "VER_NOT_FOUND"]:
            stats["not_found"] += 1
        else:
            stats["other"] += 1

        results.append({
            "name": item["display_name"],
            "kind": item["kind"],
            "installed": item["raw_version"],
            "clean_installed": item["clean_version"],
            "latest": eval_res["latest"],
            "status_text": eval_res["status"],
            "badge": eval_res["badge"],
            "code": c_code
        })

    return {
        "target": target,
        "rel_path": rel_path,
        "exists": True,
        "results": results,
        "stats": stats
    }


def print_cli_report(target_reports, json_mode=False):
    if json_mode:
        output_data = []
        for rep in target_reports:
            output_data.append({
                "id": rep["target"]["id"],
                "name": rep["target"]["name"],
                "file": rep["rel_path"],
                "exists": rep["exists"],
                "stats": rep["stats"],
                "dependencies": [
                    {
                        "name": r["name"],
                        "kind": r["kind"],
                        "installed": r["installed"],
                        "latest": r["latest"],
                        "status": r["code"],
                        "status_text": r["status_text"]
                    } for r in rep["results"]
                ]
            })
        print(json.dumps(output_data, indent=2))
        return

    print("=" * 84)
    print(f"{Colors.BOLD}{Colors.CYAN}🔍 TSARCHAIN MULTI-ECOSYSTEM DEPENDENCY CHECKER{Colors.RESET}")
    print("=" * 84)
    print(" Projects checked:")
    for rep in target_reports:
        t = rep["target"]
        st = f"{Colors.GREEN}FOUND{Colors.RESET}" if rep["exists"] else f"{Colors.RED}MISSING{Colors.RESET}"
        print(f"   • {t['icon']} {t['name']:<30} [{rep['rel_path']}] -> {st}")
    print("=" * 84)

    grand_stats = {"total": 0, "latest": 0, "update": 0, "not_found": 0, "other": 0}

    for rep in target_reports:
        t = rep["target"]
        print()
        print(f"{Colors.BOLD}----------------------------------------------------------------------------------{Colors.RESET}")
        print(f"{Colors.BOLD}{t['icon']}  {t['name'].upper()} [{rep['rel_path']}]{Colors.RESET}")
        print(f"{Colors.BOLD}----------------------------------------------------------------------------------{Colors.RESET}")

        if not rep["exists"]:
            print(f"  {Colors.YELLOW}⚠️ File does not exist: {rep['rel_path']}{Colors.RESET}")
            continue

        if not rep["results"]:
            print(f"  {Colors.GRAY}ℹ️ No dependencies declared in this file.{Colors.RESET}")
            continue

        # Print header table
        print(f"  {Colors.BOLD}{'PACKAGE':<32} {'TYPE':<8} {'INSTALLED':<12} {'LATEST':<12} {'STATUS'}{Colors.RESET}")
        print(f"  {'-'*32} {'-'*8} {'-'*12} {'-'*12} {'-'*20}")

        for r in rep["results"]:
            name_str = (r["name"][:30] + "..") if len(r["name"]) > 32 else r["name"]
            inst_str = (r["installed"][:10] + "..") if len(r["installed"]) > 12 else r["installed"]
            lat_str = (r["latest"][:10] + "..") if len(r["latest"]) > 12 else r["latest"]
            kind_str = r["kind"]
            
            print(f"  {name_str:<32} {kind_str:<8} {inst_str:<12} {lat_str:<12} {r['badge']}")

        s = rep["stats"]
        for k in grand_stats:
            grand_stats[k] += s[k]

        print("  --------------------------------------------------------------------------------")
        print(f"  Summary: {Colors.GREEN}{s['latest']} up-to-date{Colors.RESET}, "
              f"{Colors.YELLOW}{s['update']} update available{Colors.RESET}, "
              f"{Colors.RED}{s['not_found']} warnings/not found{Colors.RESET}, "
              f"{Colors.GRAY}{s['other']} other/local{Colors.RESET}")

    # Print Grand Summary Table
    print()
    print("=" * 84)
    print(f"{Colors.BOLD}📊 DEPENDENCY CHECK SUMMARY MATRIX{Colors.RESET}")
    print("=" * 84)
    print(f"  {Colors.BOLD}{'COMPONENT':<26} {'TOTAL':<8} {'UP-TO-DATE':<12} {'OUTDATED':<12} {'NOT FOUND':<12} {'OTHER'}{Colors.RESET}")
    print(f"  {'-'*26} {'-'*8} {'-'*12} {'-'*12} {'-'*12} {'-'*8}")

    for rep in target_reports:
        name_label = f"{rep['target']['icon']} {rep['target']['name']}"
        s = rep["stats"]
        print(f"  {name_label:<26} {s['total']:<8} {Colors.GREEN}{s['latest']:<12}{Colors.RESET} "
              f"{Colors.YELLOW}{s['update']:<12}{Colors.RESET} {Colors.RED}{s['not_found']:<12}{Colors.RESET} "
              f"{Colors.GRAY}{s['other']:<8}{Colors.RESET}")

    print(f"  {'-'*26} {'-'*8} {'-'*12} {'-'*12} {'-'*12} {'-'*8}")
    gs = grand_stats
    print(f"  {Colors.BOLD}{'GRAND TOTAL':<26} {gs['total']:<8} {Colors.GREEN}{gs['latest']:<12}{Colors.RESET} "
          f"{Colors.YELLOW}{gs['update']:<12}{Colors.RESET} {Colors.RED}{gs['not_found']:<12}{Colors.RESET} "
          f"{Colors.GRAY}{gs['other']:<8}{Colors.RESET}")
    print("=" * 84)

    if gs["update"] == 0 and gs["not_found"] == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}🎉 ALL DEPENDENCIES ARE UP-TO-DATE! PERFECT!{Colors.RESET}")
    else:
        notes = []
        if gs["update"] > 0:
            notes.append(f"{Colors.YELLOW}{gs['update']} update(s) available{Colors.RESET}")
        if gs["not_found"] > 0:
            notes.append(f"{Colors.RED}{gs['not_found']} warning/unresolved version(s){Colors.RESET}")
        print(f"{Colors.BOLD}💡 Status:{Colors.RESET} Found " + ", ".join(notes) + ".")
    print("=" * 84)


def main():
    parser = argparse.ArgumentParser(
        description="Check dependency versions across Python, Rust Native, Backend Web, and Frontend Web projects."
    )
    parser.add_argument("--python", "-py", action="store_true", help="Check Python dependencies (requirements.txt)")
    parser.add_argument("--rust", "-rs", action="store_true", help="Check Rust native dependencies (tsarcore_native/Cargo.toml)")
    parser.add_argument("--backend", "-be", action="store_true", help="Check Backend web dependencies (src/web/Backend/package.json)")
    parser.add_argument("--frontend", "-fe", action="store_true", help="Check Frontend web dependencies (src/web/Frontend/package.json)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--workers", type=int, default=10, help="Number of parallel request workers (default: 10)")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    print("please wait....")
    # Filter targets if specific flags provided
    selected_targets = []
    if args.python:
        selected_targets.append("python")
    if args.rust:
        selected_targets.append("rust")
    if args.backend:
        selected_targets.append("backend")
    if args.frontend:
        selected_targets.append("frontend")

    if selected_targets:
        targets_to_run = [t for t in TARGETS if t["id"] in selected_targets]
    else:
        targets_to_run = TARGETS

    target_reports = []
    for t in targets_to_run:
        rep = process_target(t, workers=args.workers)
        target_reports.append(rep)

    print_cli_report(target_reports, json_mode=args.json)

if __name__ == "__main__":
    main()