"""Loads real lab alerts exported from Wazuh (default: /var/ossec/logs/alerts/alerts.json).

    python -m src.load_wazuh path/to/alerts.json

Labels are left empty on purpose: the author labels lab alerts by hand, following
data/labeling_rule.md. Unlabelled alerts are ignored by make_splits.py.
Only use alerts from your own VMs; never employer or client data.
"""
import sys

from .common import ROOT, read_jsonl, write_jsonl
from .schema import Alert


def load(path) -> list[dict]:
    return [Alert(id=f"l{i:04d}", provenance="lab", source_note="author's lab VM", wazuh=raw).model_dump()
            for i, raw in enumerate(read_jsonl(path), 1)]


if __name__ == "__main__":
    out = ROOT / "data/parts/lab.jsonl"
    if out.exists():
        raise SystemExit(f"{out} exists and may contain hand labels; move it first.")
    rows = load(sys.argv[1])
    write_jsonl(out, rows)
    print(len(rows), "lab alerts, all unlabelled")
