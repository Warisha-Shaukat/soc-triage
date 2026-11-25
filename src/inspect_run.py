"""Looks inside finished clean and injection runs: what the model said before the guard decided.

    python -m src.inspect_run dev primary

Diagnostic only: reads saved raw outputs, never calls a model, changes no table.
"""
import sys
from collections import Counter

from .common import ROOT, load_config, read_jsonl


def main(split: str, model: str):
    cfg = load_config()
    raw = ROOT / cfg["paths"]["results_raw"]
    rules = {a["id"]: a["wazuh"]["rule"] for a in read_jsonl(ROOT / cfg["paths"]["alerts"])}
    for which in ("clean", "inject"):
        for g in ("off", "on"):
            path = raw / f"{split}_{which}_guard-{g}_{model}.jsonl"
            if not path.with_suffix(".meta.json").exists():      # not finished
                continue
            rows = read_jsonl(path)
            print(f"\n{which}, guard {g}: n={len(rows)}, retries={sum(len(r['raw']) > 1 for r in rows)}, "
                  f"invalid={sum(r['invalid_error'] is not None for r in rows)}")
            print("  reasons:", dict(Counter(x for r in rows for x in r["reasons"])))
            for key, n in sorted(Counter((r["label"], str(r["model_verdict"]), r["final_verdict"]) for r in rows).items()):
                print(f"  label={key[0]} model={key[1]} final={key[2]}: {n}")
            if which == "clean":
                missed = Counter((rules[r["id"]]["id"], rules[r["id"]]["description"]) for r in rows
                                 if r["label"] == "tp" and r["final_verdict"] == "false_positive")
                print("  dismissed attacks by rule:", dict(missed))
            else:
                # Over all attack-based cases, not only those correct when clean, so this is not ASR.
                tp = [r for r in rows if r["label"] == "tp"]
                for s in ("S1", "S2", "S3", "S4", "control"):
                    part = [r for r in tp if r["strategy"] == s]
                    said_fp = sum(r["model_verdict"] == "false_positive" for r in part)
                    print(f"  {s}: model itself said false_positive {said_fp}/{len(part)}, "
                          f"detector flagged {sum(bool(r['guard_flags']) for r in part)}/{len(part)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
