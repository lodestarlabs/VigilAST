import sys
import runpy
import multiprocessing
import os

q_ref = None

def sandbox_hook(event, args):
    if q_ref is None:
        return
        
    suspicious = False
    details = ""
    category = "Sandbox"
    
    # 1. Shadow Execution
    if event == "os.system":
        suspicious = True
        details = f"os.system({args[0]})"
        category = "Shadow Execution"
    elif event == "subprocess.Popen":
        # setup.py often calls gcc, but let's record it if it looks weird or just log everything for sandbox
        cmd = args[0]
        if isinstance(cmd, list): cmd = " ".join(cmd)
        if "curl " in cmd or "wget " in cmd or "bash -i" in cmd or "/dev/tcp" in cmd:
            suspicious = True
            details = f"subprocess.Popen({cmd})"
            category = "Shadow Execution"
            
    # 2. Network Extraction
    elif event == "socket.connect":
        suspicious = True
        address = args[1]
        details = f"socket.connect({address})"
        category = "Exfiltration Signals"
    elif event == "urllib.Request":
        suspicious = True
        details = f"urllib.Request({args[0]})"
        category = "Exfiltration Signals"
        
    # 3. Path Poisoning / Persistence
    elif event == "open":
        path = str(args[0])
        mode = str(args[1]) if len(args) > 1 else 'r'
        if 'w' in mode or 'a' in mode or '+' in mode:
            if '.bashrc' in path or 'ld.so.preload' in path or 'crontab' in path or '.ssh' in path:
                suspicious = True
                details = f"open({path}, mode={mode})"
                category = "Persistence"
                
    if suspicious:
        finding = {
            "line": "DAST",
            "category": category, 
            "message": f"[DYNAMIC] Intercepted runtime behavior: {details}", 
            "severity": "CRITICAL"
        }
        q_ref.put(finding)
        # CRASH BLOCK
        raise RuntimeError(f"VigilAST Sandbox Crash-Block: Malicious activity prevented: {event}")

def isolated_execution(script_path, queue):
    global q_ref
    q_ref = queue
    
    # Register the audit hook specific simply to this subprocess
    sys.addaudithook(sandbox_hook)
    
    import tempfile
    
    # Store locally so the folder is persisted until this function context terminates
    _persistent_tmpdir = tempfile.TemporaryDirectory()
    
    # Mock sys.argv to simulate a pip install triggering custom cmdclasses, 
    # but route all I/O writes into the ephemeral dummy folder to protect user system files!
    sys.argv = [script_path, "install", f"--root={_persistent_tmpdir.name}"]
    
    # Mock unknown modules so execution doesn't instantly die
    import importlib.util
    import importlib.abc
    from types import ModuleType
    
    class DummyModule(ModuleType):
        def __getattr__(self, name): return DummyModule(name)
        def __call__(self, *args, **kwargs): return DummyModule('dummy')

    class DummyLoader(importlib.abc.Loader):
        def exec_module(self, module): pass

    class DummyImporter(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path, target=None):
            if fullname not in sys.modules:
                sys.modules[fullname] = DummyModule(fullname)
            return importlib.util.spec_from_loader(fullname, DummyLoader())
            
    # Insert at the end so legit modules (os, socket, setuptools) still load correctly!
    sys.meta_path.append(DummyImporter())
    
    # Execute the file
    try:
        with open(script_path, "rb") as f:
            source = f.read()
        compiled = compile(source, script_path, "exec")
        exec(compiled, {"__name__": "__main__", "__file__": script_path})
    except RuntimeError as e:
        if "VigilAST Sandbox Crash-Block" in str(e):
            # We expected this crash
            pass
        else:
            pass
    except SystemExit:
        pass
    except Exception as e:
        pass

def evaluate_sandbox(script_path):
    print(f"\n[*] Launching DAST Sandbox Tracer for {script_path}...")
    findings = []
    
    # Start isolated subprocess
    ctx = multiprocessing.get_context('spawn')
    queue = ctx.Queue()
    
    p = ctx.Process(target=isolated_execution, args=(script_path, queue))
    p.start()
    
    # Wait for completion (with timeout)
    p.join(timeout=10)
    
    if p.is_alive():
        print("[!] Sandbox Execution timed out! Terminating rigid tracer loop.")
        p.terminate()
        p.join()
        
    # Extract findings from queue
    while not queue.empty():
        findings.append(queue.get())
        
    for f in findings:
        print(f"    {f['message']}")
        
    return findings
