# VigilAST
VigilAST is a behavioral analysis engine designed to secure the FOSS supply chain by auditing the structural intent of installation scripts. Unlike traditional scanners that rely on version-matching against known CVE databases, VigilAST performs deterministic Abstract Syntax Tree (AST) analysis to identify "shadow execution" patterns—such as unauthorized subprocess spawning, obfuscated network sinks, or credential harvesting—hidden within package manifests like setup.py. By evaluating the code’s structural logic rather than its signature, the tool provides a proactive defense against novel supply chain poisoning and 0-day dependency confusion attacks. To ensure rigorous safety and reproducibility, Lodestar Labs will utilize the CORE emulator and Parrot OS to simulate air-gapped CI/CD environments, allowing for the isolation and mitigation of malicious behavior within a fully contained, non-routable network.

## Features 🚀
- **Inference-Based Detection**: Uses `astroid` inference instead of simple AST, automatically defeating simple variable aliasing, unpacking, and dynamic dispatching.
- **Deep Dependency Scanning**: Recursively downloads and scans pip/uv dependencies defined in `requirements.txt` or `setup.py`.
- **Data-Flow Taint Tracking**: Natively walks variable execution flows backwards into `astroid` block scopes to ensure variables executing through Sinks (like `exec`) aren't sourced from external Sinks (like `requests.get()`).
- **Shannon Entropy Analysis**: Mathematical packet obfuscation tracking that completely outperforms legacy static Regex signatures like standard Base64 checks. 
- **Monkeypatch Injection Hooking**: Identifies stealthy attempts to inject callback functions into networking packages via `setattr` or assignment hooking.
- **Installation Hijacking Hooks**: Reads `setuptools` parameters and Class overrides to spot `cmdclass` `install` scripts executing payloads.
- **Path Poisoning & Persistence Validation**: Specifically flags string constants acting against sensitive config directories (`~/.bashrc`) or environment aliasing (`LD_PRELOAD`).
- **Typosquatting Protection**: Built-in sequence string mapping matching generic FOSS module dependencies locally.
- **PyPI Reputation Intelligence**: (Opt-In via `--reputation`) Dynamically evaluates package dependencies extracted from `requirements.txt` and `setup.py` against the real PyPI JSON registry to identify potential 0-day Dependency Confusion missing packages, brand new supply chain drops (`<7 days`), or obscured maintainer details!
- **Dynamic Execution Sandbox (DAST)**: (Opt-in via `--sandbox`) Runs untrusted setup.py package deployment sequences in an air-gapped `sys.addaudithook` pipeline, safely tracking execution footprints and invoking a rigid Crash-Block thread if suspicious outbound operations occur natively.
- **Machine Learning Classification**: (Opt-In via `--ml`) Automatically extracts discrete tracking heuristics and evaluates them over a normalized probabilistic distribution matrix (Native + Random Forest) to produce a `0.00-100%` behavioral anomaly confidence score!

## How to Run

VigilAST natively parses python source code using its AST engine. It can analyze local directories or automatically clone and analyze remote GitHub repositories. It recursively traverses the target to parse all `.py` files.

Furthermore, **VigilAST performs deep supply chain dependency scanning by default.** If it detects a `requirements.txt` (or similar file) in the target directory, it leverages `uv` or `pip` to automatically fetch all upstream packages natively, unpacks their source distributions (`.tar.gz`) or binary wheels (`.whl`), and runs AST inspection over every single file within them.

### Prerequisites
Ensure Python 3 is installed. The engine leans on `astroid` to provide deep inference tracking. You must install the requirements first:
```bash
pip install -r requirements.txt
```
Additionally, the engine relies on your system's `git` installation to clone remote repositories, and relies on `uv` or `pip` to facilitate deep-dependency resolution.

### Usage

Run the script by passing the target package directory or URL as the first argument:

```bash
# Analyze a local directory and its dependencies (e.g., to run against the included mock repository)
python vigilast.py ./mock_repo

# Analyze a remote repository and skip upstream dependency scanning
python vigilast.py https://github.com/psf/requests --skip-deps

# Enable all experimental engines (Machine Learning, PyPI Reputation Context, and DAST Sandboxing)
python vigilast.py ./mock_repo --ml --reputation --sandbox

# Export findings to an OASIS SARIF v2 JSON payload for ingestion into GitHub Advanced Security (GHAS) or SonarQube
python vigilast.py ./mock_repo --sandbox --ml --output results.sarif
```

## GitHub Actions Integration

VigilAST can act as a CI/CD pipeline blocker and is packaged as a reusable composite action. If the engine detects a potentially malicious AST behavior, it returns a non-zero exit code to fail the build instantly. 

To use VigilAST in your own repository's workflow, create a `.github/workflows/security-scan.yml` file and embed the action:

```yaml
name: Supply Chain Security Check

on:
  pull_request:
    branches: [ main ]

jobs:
  vigilast-scan:
    runs-on: 'ubuntu-latest'
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Scan with VigilAST
        uses: lodestarlabs/VigilAST@main
        with:
          target: '.'
          reputation: 'true'
          ml: 'true'
          sandbox: 'true'
```
