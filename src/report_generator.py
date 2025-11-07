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
    return None

def save_csv(report, out_dir="reports"):
    return None
