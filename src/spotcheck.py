"""Hand spot-check of labels (AGENTS.md section 9). A person fills the sheet, not a script.

    python -m src.spotcheck make     # writes data/spotcheck/sheet.csv and evidence.csv
    python -m src.spotcheck score    # compares the filled sheet with the stored labels

sheet.csv     blind: alert details, no label. Fill `your_label` with tp, fp or unsure.
evidence.csv  open AFTER the sheet is filled: stored label, why, attack window, attacker IP.
"""
import csv
import json
import random
import sys
from collections import Counter

from .common import ROOT, get_path, load_config, read_jsonl
from .load_public import epoch, phase_at, read_windows
from .metrics import exact_ci

DIR = ROOT / "data/spotcheck"
PICK = {("public", "tp"): 16, ("public", "fp"): 16, ("synthetic", "tp"): 5, ("synthetic", "fp"): 5}
SHEET = ["row", "rule_level", "rule_description", "source_ip", "user", "command_or_url", "full_log",
         "your_label", "your_note"]
EVIDENCE = ["row", "id", "split", "provenance", "stored_label", "why", "scenario", "time_utc",
            "attack_window", "inferred_attacker_ip", "source_is_attacker"]


def pick(alerts: list[dict], seed: int) -> list[dict]:
    """Round-robin over rules, so rare rules are checked too. Both splits are included."""
    rng, chosen = random.Random(f"spotcheck-{seed}"), []
    for (prov, label), n in PICK.items():
        by_rule: dict[str, list] = {}
        for a in alerts:
            if a["provenance"] == prov and a["label"] == label:
                by_rule.setdefault(a["wazuh"]["rule"]["id"], []).append(a)
        for rows in by_rule.values():
            rng.shuffle(rows)
        rules = sorted(by_rule)
        rng.shuffle(rules)
        got = [by_rule[r][d] for d in range(50) for r in rules if d < len(by_rule[r])]
        chosen += got[:n]
    rng.shuffle(chosen)                          # so the order does not give the label away
    return chosen


def save(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:      # utf-8-sig opens cleanly in Excel
        writer = csv.DictWriter(f, columns)
        writer.writeheader()
        writer.writerows(rows)


def make():
    if (DIR / "sheet.csv").exists():
        raise SystemExit("sheet.csv exists and may contain your labels; move it first.")
    cfg = load_config()
    raw = ROOT / cfg["paths"]["raw_public"] / "ait_ads"
    windows = read_windows(raw / "labels.csv")
    report = json.loads((ROOT / "data/parts/public_report.json").read_text(encoding="utf-8"))
    splits = json.loads((ROOT / cfg["paths"]["splits"]).read_text(encoding="utf-8"))
    sheet, evidence = [], []
    for row, a in enumerate(pick(read_jsonl(ROOT / cfg["paths"]["alerts"]), cfg["seed"]), 1):
        w = a["wazuh"]
        src = get_path(w, "data.srcip")
        sheet.append({
            "row": row, "rule_level": w["rule"]["level"], "rule_description": w["rule"]["description"],
            "source_ip": src, "user": get_path(w, "data.srcuser") or get_path(w, "data.dstuser"),
            "command_or_url": get_path(w, "data.command") or get_path(w, "data.url"),
            "full_log": w.get("full_log"), "your_label": "", "your_note": ""})
        ev = {"row": row, "id": a["id"], "split": next(s for s, ids in splits.items() if a["id"] in ids),
              "provenance": a["provenance"], "stored_label": a["label"], "why": a["label_note"]}
        if a["provenance"] == "public":
            scenario = a["source_note"].split("scenario=")[1]
            attacker = report[scenario]["attacker_ip"]
            ev.update(scenario=scenario, time_utc=w["@timestamp"], inferred_attacker_ip=attacker,
                      attack_window=phase_at(epoch(w), windows[scenario]) or "none",
                      source_is_attacker="yes" if src == attacker else "no" if src else "no source IP in alert")
        evidence.append(ev)
    save(DIR / "sheet.csv", SHEET, sheet)
    save(DIR / "evidence.csv", EVIDENCE, evidence)
    print(len(sheet), "alerts to check")


def score():
    def read(name):
        with open(DIR / name, encoding="utf-8-sig", newline="") as f:
            return {r["row"]: r for r in csv.DictReader(f)}
    sheet, evidence = read("sheet.csv"), read("evidence.csv")
    answers = {row: r["your_label"].strip().lower() for row, r in sheet.items()}
    bad = [row for row, label in answers.items() if label not in ("tp", "fp", "unsure", "")]
    if bad:
        raise SystemExit(f"rows with an answer other than tp / fp / unsure: {bad}")
    for prov in ("public", "synthetic"):
        rows = [r for r in evidence if evidence[r]["provenance"] == prov and answers[r]]
        judged = [r for r in rows if answers[r] != "unsure"]
        agree = [r for r in judged if answers[r] == evidence[r]["stored_label"]]
        low, high = exact_ci(len(agree), len(judged))
        interval = "" if low is None else f" exact 95% CI [{100 * low:.1f}, {100 * high:.1f}]"
        print(f"{prov}: filled {len(rows)}, unsure {len(rows) - len(judged)}, "
              f"agree {len(agree)}/{len(judged)}{interval}")
        for r in judged:
            if r not in agree:
                print(f"   row {r} ({evidence[r]['id']}): you {answers[r]}, stored {evidence[r]['stored_label']}")
    print("empty:", Counter(answers.values())[""])


if __name__ == "__main__":
    {"make": make, "score": score}[sys.argv[1]]()
