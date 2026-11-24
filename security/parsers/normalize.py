import json
import sys
from pathlib import Path

def main():
    findings = []
    semgrep_file = Path("semgrep.json")
    if semgrep_file.exists():
        data = json.loads(semgrep_file.read_text())
        for result in data.get("results", []):
            findings.append({
                "tool": "semgrep",
                "type": "SAST",
                "severity": result.get("extra", {}).get("severity"),
                "rule": result.get("check_id"),
                "message": result.get("extra", {}).get("message"),
                "file": result.get("path"),
                "line": result.get("start", {}).get("line")
            })
    output = {
        "findings": findings,
        "total": len(findings)
    }
    Path("vulnerabilities.json").write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))
    
if __name__ == "__main__":
    main()
