import astroid
from astroid.nodes import Import, ImportFrom, Call, Const, Assign, Subscript, AssignAttr, ClassDef
import argparse
import os
import sys
import tempfile
import subprocess
import re
import shutil
import zipfile
import tarfile
import difflib
import math
import json
import urllib.request
from datetime import datetime, timezone
from astroid.exceptions import InferenceError

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

# Categorized Targets
POPULAR_PACKAGES = {
    'requests', 'urllib3', 'boto3', 'flask', 'django', 'numpy', 
    'pandas', 'tensorflow', 'scipy', 'pytorch', 'matplotlib', 
    'setuptools', 'beautifulsoup4', 'pytest', 'colorama'
}
SHADOW_EXECUTION_IMPORTS = {'subprocess', 'pty'}
SHADOW_EXECUTION_CALLS = {'os.system', 'os.popen', 'subprocess.run', 'subprocess.call', 'subprocess.Popen'}

OBFUSCATION_IMPORTS = {'base64', 'codecs'}
OBFUSCATION_CALLS = {'builtins.exec', 'builtins.eval', 'builtins.compile', 'builtins.__import__', 'builtins.open', 'base64.b64decode'}

MONKEYPATCH_TARGETS = {'get', 'post', 'request', 'urlopen', 'send', 'Session'}
NETWORK_MODULES = ('requests', 'urllib', 'http', 'socket')

# Regex patterns for Constants (strings/bytes)
EXFIL_DOMAINS = re.compile(r'(pastebin\.com|discord\.com/api/webhooks|api\.telegram\.org)', re.IGNORECASE)
EXFIL_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CRED_TARGETS = re.compile(r'(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|npm_token|SSH_AUTH_SOCK|\.ssh/id_rsa)', re.IGNORECASE)
PERSISTENCE_TARGETS = re.compile(r'(\.bashrc|\.zshrc|\.profile|crontab|\.config/autostart|/etc/ld\.so\.preload)', re.IGNORECASE)

CHECK_REPUTATION = False
RUN_SANDBOX = False

def check_pypi_reputation(package_name):
    pkg_clean = re.split(r'[<>=]', package_name)[0].strip()
    if not pkg_clean: return []
    url = f"https://pypi.org/pypi/{pkg_clean}/json"
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'VigilAST'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            info = data.get("info", {})
            releases = data.get("releases", {})
            if releases:
                try:
                    first_release_time = min(r[0]['upload_time_iso_8601'] for r in releases.values() if r)
                    dt = datetime.fromisoformat(first_release_time.replace('Z', '+00:00'))
                    age_days = (datetime.now(timezone.utc) - dt).days
                    if age_days < 7:
                        findings.append({"severity": "HIGH", "category": "PyPI Reputation", "message": f"Brand new package released {age_days} days ago: {pkg_clean}"})
                except Exception:
                    pass
            if not info.get("home_page") and not info.get("project_url"):
                findings.append({"severity": "MEDIUM", "category": "PyPI Reputation", "message": f"Missing prominent project URLs/homepages for package: {pkg_clean}"})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            findings.append({"severity": "CRITICAL", "category": "Dependency Confusion", "message": f"Package '{pkg_clean}' does not exist on PyPI registry! Potential 0-day drop target."})
    except Exception:
        pass
    return findings

def analyze_file(filepath):
    print(f"[*] Analyzing {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()
        
    try:
        module = astroid.parse(source, path=filepath)
    except Exception as e:
        print(f"[!] Failed to parse AST for {filepath}: {e}")
        return []
        
    findings = []
    def add_finding(node, category, message, severity="HIGH"):
        findings.append({
            'line': getattr(node, 'lineno', -1),
            'category': category,
            'message': message,
            'severity': severity
        })

    def check_typosquat(module_name, node):
        if not module_name: return
        if module_name in POPULAR_PACKAGES: return
        
        for pkg in POPULAR_PACKAGES:
            ratio = difflib.SequenceMatcher(None, module_name, pkg).ratio()
            # 0.8 is roughly a 1-2 character transpose in a standard 8-char package name
            if 0.8 <= ratio < 1.0:
                add_finding(node, "Typosquatting", f"Import '{module_name}' is suspiciously similar to popular package '{pkg}'", "HIGH")
                
    def trace_taint(target_node, depth=0):
        if depth > 5:
            return None
            
        if hasattr(target_node, 'name'):
            try:
                assigns = target_node.lookup(target_node.name)[1]
                for assign in assigns:
                    if hasattr(assign, 'parent') and hasattr(assign.parent, 'value'):
                        result = trace_taint(assign.parent.value, depth + 1)
                        if result:
                            return result
            except Exception:
                pass
        elif isinstance(target_node, Call):
            try:
                # If there's an outer method call like .read() or .text, infer the inner object if possible.
                # Actually astroid handles this if we infer the function being called.
                for inferred in target_node.func.infer():
                    if hasattr(inferred, 'qname'):
                        qname = inferred.qname()
                        # If it's a built-in string method like read() on an uninferable socket, 
                        # astroid might fail. Let's provide a fallback string match just in case.
                        if any(qname.startswith(p) for p in NETWORK_MODULES):
                            return qname
                
                # Fallback to string representation if infer fails
                func_name = target_node.func.as_string()
                if any(p in func_name for p in NETWORK_MODULES):
                    return func_name
            except Exception:
                pass
        return None

    for node in module.nodes_of_class((Import, ImportFrom, Call, Const, Assign, ClassDef)):
        if isinstance(node, Import):
            for name, _ in node.names:
                check_typosquat(name, node)
                if name in SHADOW_EXECUTION_IMPORTS:
                    add_finding(node, "Shadow Execution", f"Suspicious module imported: {name}", "MEDIUM")
                elif name in OBFUSCATION_IMPORTS:
                    add_finding(node, "Anti-Analysis", f"Obfuscation module imported: {name}", "MEDIUM")
                elif name in {'socket', 'urllib', 'requests', 'http'}:
                     add_finding(node, "Exfiltration Signals", f"Network root module imported: {name}", "LOW")
                     
        elif isinstance(node, ImportFrom):
            check_typosquat(node.modname, node)
            if node.modname in SHADOW_EXECUTION_IMPORTS:
                add_finding(node, "Shadow Execution", f"Suspicious module imported from {node.modname}", "MEDIUM")
            elif node.modname in OBFUSCATION_IMPORTS:
                add_finding(node, "Anti-Analysis", f"Obfuscation module imported from {node.modname}", "MEDIUM")
            elif node.modname in {'socket', 'urllib', 'requests', 'http'}:
                 add_finding(node, "Exfiltration Signals", f"Network root module imported from {node.modname}", "LOW")
                 
        elif isinstance(node, Call):
            try:
                func_name_str = node.func.as_string()
                
                # Check for cmdclass hook injection in setup()
                if func_name_str.endswith('setup') and node.keywords:
                    for kw in node.keywords:
                        if kw.arg == 'cmdclass':
                            add_finding(node, "Installation Hijacking", f"setup() overriding default installation behavior via 'cmdclass'", "HIGH")
                        if kw.arg == 'install_requires' and CHECK_REPUTATION:
                            if hasattr(kw.value, 'elts'):
                                for elt in kw.value.elts:
                                    if isinstance(elt, Const) and isinstance(elt.value, str):
                                        pypi_findings = check_pypi_reputation(elt.value)
                                        for pf in pypi_findings:
                                            add_finding(node, pf['category'], pf['message'], pf['severity'])
                            
                # Catch setattr monkeypatching
                if func_name_str == 'setattr' and len(node.args) >= 2:
                    mod_name = node.args[0].as_string()
                    if isinstance(node.args[1], Const):
                        attr_name = node.args[1].value
                        if attr_name in MONKEYPATCH_TARGETS and any(mod_name.startswith(p) for p in NETWORK_MODULES):
                            add_finding(node, "Monkeypatching", f"Dynamic callback injection (setattr) detected on: {mod_name}.{attr_name}", "CRITICAL")
                            
                # Target the function itself, inference defeats simple aliasing
                for inferred in node.func.infer():
                    if not hasattr(inferred, 'qname'):
                        continue
                    qname = inferred.qname()
                    
                    if qname in OBFUSCATION_CALLS:
                        add_finding(node, "Anti-Analysis", f"Dangerous built-in function called: {qname}()", "CRITICAL")
                        
                        # Defeat payload concatenation by inferring what was passed to exec() or b64decode()
                        if node.args:
                            for arg_inferred in node.args[0].infer():
                                if isinstance(arg_inferred, Const) and isinstance(arg_inferred.value, (str, bytes)):
                                    v = arg_inferred.value.decode('utf-8', errors='ignore') if isinstance(arg_inferred.value, bytes) else arg_inferred.value
                                    if len(v) > 64:
                                        entropy = shannon_entropy(v)
                                        if entropy > 5.5:
                                            add_finding(node, "Anti-Analysis", f"Inferred encoded payload dynamically passed to {qname}() (Entropy: {entropy:.2f})", "CRITICAL")
                                            
                        if node.args:
                            for arg in node.args:
                                taint_source = trace_taint(arg)
                                if taint_source:
                                    add_finding(node, "Anti-Analysis", f"Tainted variable passed to {qname}() originating from network call: {taint_source}", "CRITICAL")
                                        
                    elif qname in SHADOW_EXECUTION_CALLS:
                        add_finding(node, "Shadow Execution", f"System command execution detected: {qname}()", "CRITICAL")
                        
                        if node.args:
                            for arg in node.args:
                                taint_source = trace_taint(arg)
                                if taint_source:
                                    add_finding(node, "Shadow Execution", f"Tainted variable passed to {qname}() originating from network call: {taint_source}", "CRITICAL")
            except InferenceError:
                pass
                
        elif isinstance(node, Const):
            val = node.value
            if isinstance(val, (str, bytes)):
                v = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else val
                
                if EXFIL_DOMAINS.search(v):
                    add_finding(node, "Exfiltration Signals", f"Suspicious domain detected: {v[:50]}", "CRITICAL")
                elif EXFIL_IP.search(v):
                    add_finding(node, "Exfiltration Signals", f"Hardcoded IP Address detected: {v[:30]}", "HIGH")
                    
                if CRED_TARGETS.search(v):
                    add_finding(node, "Credential Harvesting", f"Targeting sensitive data/environment variable: {v}", "CRITICAL")
                    
                if PERSISTENCE_TARGETS.search(v):
                    add_finding(node, "Persistence", f"Targeting persistence configuration file: {v[:50]}", "CRITICAL")
                    
                if len(v) > 64:
                    entropy = shannon_entropy(v)
                    if entropy > 5.5:
                        add_finding(node, "Anti-Analysis", f"Highly entropic string detected (Entropy: {entropy:.2f}). Possible packed/encrypted payload.", "HIGH")

        elif isinstance(node, Assign):
            for target in node.targets:
                if isinstance(target, Subscript):
                    try:
                        if target.value.as_string().endswith('.environ'):
                            slice_val = target.slice.as_string().strip("\"'")
                            if slice_val in ('PATH', 'LD_PRELOAD', 'PYTHONPATH'):
                                add_finding(node, "Path Poisoning", f"Suspicious persistence assignment to environment variable: {slice_val}", "CRITICAL")
                    except Exception:
                        pass
                
                elif isinstance(target, AssignAttr):
                    try:
                        expr_name = target.expr.as_string()
                        if target.attrname in MONKEYPATCH_TARGETS and any(expr_name.startswith(p) for p in NETWORK_MODULES):
                            add_finding(node, "Monkeypatching", f"Dynamic callback injection (attribute assignment) detected on: {expr_name}.{target.attrname}", "CRITICAL")
                    except Exception:
                        pass
                        
        elif isinstance(node, ClassDef):
            # Check for Installation Hijacking via custom setup commands
            try:
                for base in node.bases:
                    if base.as_string() in ('install', 'develop', 'build_ext', 'build'):
                        for method in node.mymethods():
                            if method.name == 'run':
                                add_finding(node, "Installation Hijacking", f"Custom setup command class '{node.name}' inheriting '{base.as_string()}' overriding run()", "HIGH")
            except Exception:
                pass

    return findings

def process_target(target):
    # Check if target is a URL
    if target.startswith("http://") or target.startswith("https://"):
        print(f"[*] Target is a remote repository: {target}")
        temp_dir = tempfile.mkdtemp(prefix="vigilast_")
        print(f"[*] Cloning repository to temporary directory: {temp_dir}")
        try:
            subprocess.check_call(
                ["git", "clone", "--depth", "1", target, temp_dir], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            return process_directory(temp_dir), temp_dir, temp_dir
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to clone repository: {e}")
            sys.exit(1)
    else:
        return process_directory(target), target, None

def process_directory(path):
    findings_map = {}
    
    if os.path.isfile(path):
        if path.endswith('.py'):
            findings_map[path] = analyze_file(path)
        return findings_map
        
    for root, _, files in os.walk(path):
        if '.git' in root or '.venv' in root or '__pycache__' in root:
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                findings = analyze_file(filepath)
                
                if RUN_SANDBOX and file == "setup.py":
                    try:
                        import vigilast_sandbox
                        df = vigilast_sandbox.evaluate_sandbox(filepath)
                        findings.extend(df)
                    except Exception as e:
                        print(f"[!] Sandbox failed: {e}")
                        
                findings_map[filepath] = findings
                
    if not findings_map:
        print(f"[!] No .py files found in {path}")
        
    return findings_map

def download_and_extract_deps(repo_path, findings_map):
    req_file = os.path.join(repo_path, "requirements.txt")
    if not os.path.exists(req_file):
        return None
        
    print(f"\n[*] Found requirements.txt. Fetching upstream dependencies for deep analysis...")
    
    # Check reputation
    if CHECK_REPUTATION:
        req_findings = []
        with open(req_file, 'r', encoding='utf-8') as rf:
            for i, line in enumerate(rf):
                line = line.strip()
                if line and not line.startswith('#'):
                    pypi_findings = check_pypi_reputation(line)
                    for pf in pypi_findings:
                        req_findings.append({
                            'line': i + 1,
                            'category': pf['category'],
                            'message': pf['message'],
                            'severity': pf['severity']
                        })
        if req_findings:
            findings_map[req_file] = req_findings
            
    deps_base_dir = tempfile.mkdtemp(prefix="vigilast_deps_")
    download_dir = os.path.join(deps_base_dir, "downloads")
    extract_dir = os.path.join(deps_base_dir, "extracted")
    os.makedirs(download_dir)
    os.makedirs(extract_dir)
    
    cmd = []
    if shutil.which("uv"):
        print("[*] Using 'uv' for dependency resolution and downloading.")
        cmd = ["uv", "pip", "download", "-d", download_dir, "-r", req_file]
    elif shutil.which("pip"):
        print("[*] Using 'pip' for dependency downloading.")
        cmd = ["pip", "download", "-d", download_dir, "-r", req_file]
    else:
        print("[!] Neither 'uv' nor 'pip' found. Skipping dependency scan.")
        shutil.rmtree(deps_base_dir, ignore_errors=True)
        return None
        
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[!] Warning: Failed to cleanly download some dependencies: {e}")
        pass
        
    downloads = os.listdir(download_dir)
    if not downloads:
        print("[*] No dependencies were downloaded.")
        shutil.rmtree(deps_base_dir, ignore_errors=True)
        return None
        
    print(f"[*] Extracting {len(downloads)} dependency packages for AST scanning...")
    for dl in downloads:
        dl_path = os.path.join(download_dir, dl)
        try:
            if dl.endswith('.whl') or dl.endswith('.zip'):
                with zipfile.ZipFile(dl_path, 'r') as zip_ref:
                    zip_ref.extractall(os.path.join(extract_dir, dl))
            elif dl.endswith('.tar.gz') or dl.endswith('.tgz') or dl.endswith('.tar'):
                with tarfile.open(dl_path, 'r:*') as tar_ref:
                    tar_ref.extractall(os.path.join(extract_dir, dl))
        except Exception as e:
            print(f"[!] Error extracting {dl}: {e}")
            
    return deps_base_dir, extract_dir

def main():
    parser = argparse.ArgumentParser(description="VigilAST: Behavioral AST analysis for Python install scripts.")
    parser.add_argument("target", help="Local directory or GitHub repository URL to analyze.")
    parser.add_argument("--skip-deps", action="store_true", help="Skip downloading and analyzing upstream dependencies.")
    parser.add_argument("--output", type=str, help="Output file for SARIF JSON report (e.g. results.sarif)")
    parser.add_argument("--reputation", action="store_true", help="Query the PyPI registry for author/release reputation scoring.")
    parser.add_argument("--ml", action="store_true", help="Launch the scikit-learn anomaly prediction classifier.")
    parser.add_argument("--sandbox", action="store_true", help="Launch suspicious setup.py files inside an isolated DAST audit hook tracer.")
    args = parser.parse_args()
    
    global CHECK_REPUTATION
    global RUN_SANDBOX
    if args.reputation:
        CHECK_REPUTATION = True
    if args.sandbox:
        RUN_SANDBOX = True

    # 1. Process target repo
    findings_map, repo_path, repo_temp_dir = process_target(args.target)
    
    # 2. Process dependencies
    deps_temp_dir = None
    if not args.skip_deps:
        deps_info = download_and_extract_deps(repo_path, findings_map)
        if deps_info:
            deps_base, deps_extract = deps_info
            deps_temp_dir = deps_base
            deps_findings = process_directory(deps_extract)
            findings_map.update(deps_findings)
    else:
        print("\n[*] Skipping dependency scan due to --skip-deps flag.")
        
    # 3. Report
    total_findings = 0
    clean_repo_files = 0
    clean_dep_files = 0
    
    for file, findings in findings_map.items():
        if findings:
            print(f"\n[!] ALERT: Malicious/Suspicious patterns found in {file}!")
            for f in findings:
                print(f"    Line {f['line']:<4} [{f['severity']:<8}] [{f['category']}] : {f['message']}")
                total_findings += 1
        else:
            if repo_temp_dir and file.startswith(repo_temp_dir) or (not repo_temp_dir and file.startswith(repo_path)):
                clean_repo_files += 1
            else:
                clean_dep_files += 1
                
    if clean_repo_files > 0:
        print(f"\n[*] Clean: No suspicious AST patterns found in {clean_repo_files} target files.")
    if clean_dep_files > 0:
        print(f"[*] Clean: No suspicious AST patterns found in {clean_dep_files} upstream dependency files.")

    # 4. Cleanup
    if repo_temp_dir:
        print(f"\n[*] Cleaning up repository temporary directory...")
        shutil.rmtree(repo_temp_dir, ignore_errors=True)
    if deps_temp_dir:
        print(f"[*] Cleaning up dependencies temporary directory...")
        shutil.rmtree(deps_temp_dir, ignore_errors=True)

    print(f"\n[*] Analysis complete. Total findings: {total_findings}")
    
    # 5. Machine Learning Integration
    if args.ml:
        try:
            import vigilast_ml
            vigilast_ml.run_ml_evaluation(findings_map)
        except ImportError:
            print("[!] Could not load Machine Learning module! Make sure 'scikit-learn' is installed.")
            
    # 6. Export Report
    if args.output:
        sarif_log = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VigilAST",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/lodestarlabs/VigilAST",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note"
        }
        
        for file, findings in findings_map.items():
            if not findings: continue
            for f in findings:
                sarif_log["runs"][0]["results"].append({
                    "ruleId": f["category"].replace(" ", "-"),
                    "level": level_map.get(f["severity"], "warning"),
                    "message": {
                        "text": f["message"]
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file.replace("\\", "/")
                            },
                            "region": {
                                "startLine": f["line"]
                            }
                        }
                    }]
                })
                
        try:
            with open(args.output, 'w', encoding='utf-8') as sf:
                json.dump(sarif_log, sf, indent=2)
            print(f"[*] SARIF report successfully written to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write SARIF report: {e}")

    if total_findings > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
