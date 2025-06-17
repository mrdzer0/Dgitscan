import re
import yaml

def load_signatures(file_path="scanner_plugins/config.yaml"):
    with open(file_path, "r") as f:
        data = yaml.safe_load(f)
    sigs = data.get("signatures", {})
    weights = {k: sigs[k].get("weight", 10) if isinstance(sigs[k], dict) else 10 for k in sigs}
    patterns = {k: sigs[k]["pattern"] if isinstance(sigs[k], dict) else sigs[k] for k in sigs}
    return patterns, weights

def run_signature_engine(text, signatures):
    findings = []
    for label, pattern in signatures.items():
        try:
            matches = re.findall(pattern, text)
            if matches:
                if isinstance(matches[0], tuple):
                    matches = [''.join(m) for m in matches]
                findings.append({
                    "type": label,
                    "matches": list(set(matches))
                })
        except re.error as err:
            print(f"[!] Regex error in signature '{label}': {err}")
    return findings

def calculate_risk_score(findings, weights):
    score = 0
    for finding in findings:
        score += weights.get(finding["type"], 10) * len(finding["matches"])
    return score