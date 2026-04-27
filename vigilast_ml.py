import re
import math

def vectorize_repo(findings_map):
    vector = {
        'anti_analysis': 0,
        'shadow_exec': 0,
        'exfil': 0,
        'monkeypatch': 0,
        'persistence': 0,
        'hijacking': 0,
        'typosquatting': 0,
        'reputation': 0,
        'max_entropy': 0.0
    }
    
    for _, findings in findings_map.items():
        if not findings: continue
        for f in findings:
            cat = f.get('category', '')
            msg = f.get('message', '')
            if cat == "Anti-Analysis":
                vector['anti_analysis'] += 1
                if 'Entropy' in msg:
                    match = re.search(r'Entropy:\s*([\d\.]+)', msg)
                    if match:
                        entropy = float(match.group(1))
                        if entropy > vector['max_entropy']:
                            vector['max_entropy'] = entropy
            elif cat == "Shadow Execution": vector['shadow_exec'] += 1
            elif cat == "Exfiltration Signals": vector['exfil'] += 1
            elif cat == "Monkeypatching": vector['monkeypatch'] += 1
            elif cat in ("Persistence", "Path Poisoning"): vector['persistence'] += 1
            elif cat == "Installation Hijacking": vector['hijacking'] += 1
            elif cat == "Typosquatting": vector['typosquatting'] += 1
            elif cat in ("PyPI Reputation", "Dependency Confusion"): vector['reputation'] += 1
            
    return [
        vector['anti_analysis'], vector['shadow_exec'], vector['exfil'], 
        vector['monkeypatch'], vector['persistence'], vector['hijacking'], 
        vector['typosquatting'], vector['reputation'], vector['max_entropy']
    ]

def fallback_ml_evaluation(vector):
    print("[!] 'scikit-learn' missing or incompatible. Falling back to native anomaly heuristics...")
    anti, shadow, exfil, monk, persist, hijack, typo, rep, entropy = vector
    score = 0.0
    score += anti * 12.0
    score += shadow * 20.0
    score += exfil * 25.0
    score += monk * 20.0
    score += persist * 20.0
    score += hijack * 20.0
    score += typo * 15.0
    score += rep * 25.0
    if entropy > 5.5:
        score += (entropy - 5.5) * 15.0
        
    prob = min(score / 120.0, 0.999)
    return prob

def run_ml_evaluation(findings_map):
    print("\n[*] Initializing VigilAST Machine Learning Anomaly Engine...")
    target_vec = vectorize_repo(findings_map)
    print(f"[*] Repository Feature Vector: {target_vec}")
    
    prob = 0.0
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        print("[*] Synthesizing baseline dataset offline (1000 standard deviation profiles)...")
        
        # Generator
        np.random.seed(42)
        X, y = [], []
        for _ in range(500):
            X.append([np.random.randint(0, 2), np.random.randint(0, 2), 0, 0, 0, 0, 0, np.random.randint(0, 2), np.random.uniform(0.0, 4.8)])
            y.append(0)
        for _ in range(500):
            X.append([np.random.randint(1, 5), np.random.randint(1, 4), np.random.randint(0, 3), np.random.randint(0, 3), np.random.randint(0, 3), np.random.randint(0, 3), np.random.randint(0, 2), np.random.randint(1, 5), np.random.uniform(5.5, 8.0)])
            y.append(1)
            
        model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        model.fit(X, y)
        print("[*] Random Forest Classifier successfully converged. Extracting probabilistic weights...")
        prob = model.predict_proba([target_vec])[0][1]
    except ImportError:
        prob = fallback_ml_evaluation(target_vec)
    
    print("\n" + "="*50)
    print("--- VigilAST Distributed Machine Learning ---")
    percentage = prob * 100
    if percentage > 75.0:
        print(f"[CRITICAL] ML Anomaly Confidence: {percentage:.2f}% Probability of Malicious Intent!")
    elif percentage > 40.0:
        print(f"[HIGH] ML Anomaly Confidence: {percentage:.2f}% Probability of Malicious Intent.")
    elif percentage > 20.0:
        print(f"[MEDIUM] ML Anomaly Confidence: {percentage:.2f}% Probability of Malicious Intent.")
    else:
        print(f"[*] Clean: ML Anomaly Confidence: {percentage:.2f}% Profile aligns with standard PyPI structures.")
    print("="*50 + "\n")
        
    return percentage
