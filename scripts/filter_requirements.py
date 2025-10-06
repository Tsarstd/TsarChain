# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
import subprocess
import re
import os

def get_used_imports():
    used_packages = set()
    
    std_lib = {'os', 'sys', 'math', 'json', 'datetime', 're', 'time', 
               'random', 'pathlib', 'typing', 'collections', 'itertools',
               'argparse', 'logging', 'subprocess', 'threading', 'multiprocessing',
               'csv', 'io', 'functools', 'hashlib', 'ssl', 'socket', 'urllib'}
    
    ignore_dirs = {'.venv', 'venv', 'env', 'virtualenv', '__pycache__', 
                  '.git', '.vscode', '.idea', 'node_modules', 'dist', 'build'}
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        imports = re.findall(r'^(?:from|import)\s+(\w+)', content, re.MULTILINE)
                        for imp in imports:
                            if imp not in std_lib:
                                used_packages.add(imp.lower())
                except UnicodeDecodeError:
                    try:
                        with open(filepath, 'r', encoding='latin-1') as f:
                            content = f.read()
                            imports = re.findall(r'^(?:from|import)\s+(\w+)(?:\s+|\.|$)', content, re.MULTILINE)
                            for imp in imports:
                                if imp not in std_lib:
                                    used_packages.add(imp.lower())
                    except:
                        continue
                except:
                    continue
    
    return used_packages

def generate_clean_requirements():
    result = subprocess.run(['pip', 'freeze'], capture_output=True, text=True)
    all_packages = result.stdout.split('\n')
    used_packages = get_used_imports()
    with open('requirements.txt', 'w', encoding='utf-8') as f:
        for package in all_packages:
            if package and '==' in package:
                pkg_name = package.split('==')[0].lower().replace('_', '-')
                if pkg_name in used_packages:
                    f.write(package + '\n')
                    print(f"✅ Included: {package}")
                    

if __name__ == "__main__":
    generate_clean_requirements()