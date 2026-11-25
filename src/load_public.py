"""Loader for the AIT Alert Data Set (Zenodo 8263181, CC-BY-4.0).

AIT-ADS gives attack time windows, not per-alert labels. The rule in
data/labeling_rule.md turns them into tp / fp / excluded:

  tp        inside an attack window AND (source IP is the scenario's attacker
            OR it is a su/sudo/pam alert inside the privilege-escalation window)
  fp        more than MARGIN seconds away from every attack window
  excluded  everything else (benign noise during an attack, unclear attribution)

Suricata alerts (re-ingested by Wazuh) are dropped: the spec asks for Wazuh alerts.

    python -m src.load_public       # reads data/raw/ait_ads/, writes data/parts/public.jsonl
"""
import csv
import io
import json
import random
import zipfile
from collections import Counter, defaultdict
from datetime import datetime

from .common import ROOT, load_config, sha256_text, write_jsonl
from .schema import Alert

SOURCE = ("AIT Alert Data Set (AIT-ADS) v1, https://zenodo.org/records/8263181, CC-BY-4.0, "
          "Landauer et al. 2024, doi:10.1145/3675741.3675748; testbed data; scenario={}")
MARGIN = 3600
HOST_DECODERS = {"su", "sudo", "pam"}
# dirb = the loudest phase: one client requests thousands of missing pages.
ATTACKER_PHASE = "dirb"
MIN_ATTACKER_SHARE = 0.95
PER_LABEL = 120           # public alerts wanted per label (max_per_rule may make it fewer)


def read_windows(labels_csv) -> dict[str, list[tuple[str, float, float]]]:
    windows = defaultdict(list)
    with open(labels_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            windows[row["scenario"]].append((row["attack"], float(row["start"]), float(row["end"])))
    return windows


def stream(archive: zipfile.ZipFile, name: str):
    with archive.open(name) as f:
        for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
            if line.strip():
                yield json.loads(line)


def epoch(alert: dict) -> float:
    return datetime.fromisoformat(alert["@timestamp"].replace("Z", "+00:00")).timestamp()


def phase_at(ts: float, windows) -> str | None:
    return next((name for name, start, end in windows if start <= ts <= end), None)


def near_attack(ts: float, windows) -> bool:
    return any(start - MARGIN <= ts <= end + MARGIN for _, start, end in windows)


def is_suricata(alert: dict) -> bool:
    return "suricata" in str(alert.get("location", "")).lower() or \
           "suricata" in str(alert["rule"].get("description", "")).lower()


def find_attacker_ip(alerts, windows) -> tuple[str | None, float]:
    """The source IP behind almost all web alerts in the dirb window, else None."""
    hits = Counter()
    for a in alerts:
        if a.get("decoder", {}).get("name") == "web-accesslog" and phase_at(epoch(a), windows) == ATTACKER_PHASE:
            hits[a.get("data", {}).get("srcip")] += 1
    if not hits:
        return None, 0.0
    ip, count = hits.most_common(1)[0]
    share = count / sum(hits.values())
    return (ip, share) if share >= MIN_ATTACKER_SHARE else (None, share)


def label_alert(alert: dict, windows, attacker_ip) -> tuple[str | None, str]:
    """Returns (label or None, reason)."""
    ts = epoch(alert)
    phase = phase_at(ts, windows)
    if phase:
        if attacker_ip and alert.get("data", {}).get("srcip") == attacker_ip:
            return "tp", f"phase={phase}; source is the scenario attacker"
        if phase == "privilege_escalation" and alert.get("decoder", {}).get("name") in HOST_DECODERS:
            return "tp", f"phase={phase}; host authentication alert"
        return None, "in window, not attributable to attacker"
    if near_attack(ts, windows):
        return None, "within margin of a window"
    if attacker_ip and alert.get("data", {}).get("srcip") == attacker_ip:
        return None, "attacker IP outside windows"
    return "fp", "outside all attack windows"


def sample(pool: list[dict], per_label: int, max_per_rule: int, rng) -> list[dict]:
    """Round-robin over rules, so common rules do not crowd out rare ones."""
    chosen = []
    for label in ("tp", "fp"):
        by_rule = defaultdict(list)
        for row in pool:
            if row["label"] == label:
                by_rule[row["wazuh"]["rule"]["id"]].append(row)
        for rows in by_rule.values():
            rows.sort(key=lambda r: r["_key"])          # file order must not matter
            rng.shuffle(rows)
        picked, depth = [], 0
        while len(picked) < per_label and depth < max_per_rule:
            for rule in sorted(by_rule):
                if depth < len(by_rule[rule]) and len(picked) < per_label:
                    picked.append(by_rule[rule][depth])
            depth += 1
        chosen += picked
    return chosen


def main():
    cfg = load_config()
    raw = ROOT / cfg["paths"]["raw_public"] / "ait_ads"
    windows_all = read_windows(raw / "labels.csv")
    rng, pool, seen, report = random.Random(cfg["seed"]), [], set(), {}
    keep_per_cell = 200      # reservoir per (scenario, rule, label): bounds memory, still random
    with zipfile.ZipFile(raw / "ait_ads.zip") as archive:
        for name in sorted(n for n in archive.namelist() if n.endswith("_wazuh.json")):
            scenario = name.split("/")[-1].removesuffix("_wazuh.json")
            windows = windows_all[scenario]
            attacker, share = find_attacker_ip(stream(archive, name), windows)
            stats, cells, cell_seen = Counter(), defaultdict(list), Counter()
            for a in stream(archive, name):
                stats["total"] += 1
                if is_suricata(a):
                    stats["dropped: suricata"] += 1
                    continue
                label, why = label_alert(a, windows, attacker)
                if label is None:
                    stats["excluded: " + why] += 1
                    continue
                key = sha256_text(a["rule"]["id"] + "\x00" + str(a.get("full_log")))
                if key in seen:
                    stats["dropped: exact duplicate text"] += 1
                    continue
                seen.add(key)
                stats["usable " + label] += 1
                cell = (a["rule"]["id"], label)
                cell_seen[cell] += 1
                row = {"_key": key, "label": label, "label_note": why, "scenario": scenario, "wazuh": a}
                if len(cells[cell]) < keep_per_cell:
                    cells[cell].append(row)
                else:                                    # reservoir sampling
                    j = rng.randrange(cell_seen[cell])
                    if j < keep_per_cell:
                        cells[cell][j] = row
            report[scenario] = {"attacker_ip": attacker, "attacker_share": round(share, 4), **stats}
            print(scenario, json.dumps(report[scenario]), flush=True)
            pool += [r for rows in cells.values() for r in rows]

    chosen = sample(pool, PER_LABEL, cfg["data"]["max_per_rule"], rng)
    out = []
    for i, r in enumerate(sorted(chosen, key=lambda r: r["_key"]), 1):
        mitre = r["wazuh"]["rule"].get("mitre", {}).get("id") or [None]
        out.append(Alert(id=f"p{i:04d}", provenance="public", source_note=SOURCE.format(r["scenario"]),
                         wazuh=r["wazuh"], label=r["label"], label_note=r["label_note"],
                         # Wazuh's own ATT&CK tag, not ground truth; only kept for attacks.
                         technique=mitre[0] if r["label"] == "tp" else None).model_dump())
    write_jsonl(ROOT / "data/parts/public.jsonl", out)
    (ROOT / "data/parts/public_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("chosen:", Counter((r["label"], r["wazuh"]["rule"]["id"]) for r in out))


if __name__ == "__main__":
    main()
