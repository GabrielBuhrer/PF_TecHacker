import json
import csv
from datetime import datetime
from pathlib import Path

def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_json(report, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = f"{out_dir}/scan_{_ts()}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path

def save_md(report, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    s = report.get("scan_summary", {})
    lines = [
        "# Scan Report", "",
        "## Summary",
        f"- Target: {s.get('target_url','-')}",
        f"- Date: {s.get('scan_date','-')}",
        f"- Duration: {s.get('duration_seconds','-')}s",
        f"- URLs scanned: {s.get('urls_scanned','-')}",
        f"- Findings: {s.get('vulnerabilities_found','-')}", "",
        "## Findings"
    ]
    for v in report.get("vulnerabilities", []):
        lines.append(f"- **{v.get('type','?')}** @ {v.get('url','?')} "
                     f"({v.get('parameter','-')}) — {v.get('severity','?')}")
    path = f"{out_dir}/scan_{_ts()}.md"
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    return path

def save_csv(report, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = f"{out_dir}/scan_{_ts()}.csv"
    fields = ["type","url","parameter","severity","evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for v in report.get("vulnerabilities", []):
            w.writerow({k: v.get(k,"") for k in fields})
    return path
