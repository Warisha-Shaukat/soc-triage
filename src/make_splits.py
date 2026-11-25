"""Joins the data parts into alerts.jsonl and makes the fixed dev/test split.

All alerts of one rule.id go to the same split, so test is not a near-copy of dev.
Whole groups are assigned greedily so that each (provenance, label) count is close
to the target share in both splits.
"""
import json
import random
from collections import Counter, defaultdict

from .common import ROOT, load_config, read_jsonl, write_jsonl


def group_key(alert: dict) -> str:
    return f"{alert['provenance']}:{alert['wazuh']['rule']['id']}"


def make_splits(alerts: list[dict], test_fraction: float, seed: int) -> dict[str, list[str]]:
    groups = defaultdict(list)
    for a in alerts:
        groups[group_key(a)].append(a)
    cell = lambda a: (a["provenance"], a["label"])                    # noqa: E731
    target = {c: n * test_fraction for c, n in Counter(map(cell, alerts)).items()}

    order = sorted(groups)
    random.Random(seed).shuffle(order)
    order.sort(key=lambda k: -len(groups[k]))                         # big groups first (stable sort)
    test_count, test_keys = Counter(), set()
    for key in order:
        add = Counter(map(cell, groups[key]))
        # Distance to target with and without this group; take it if that brings us closer.
        without = sum((test_count[c] - target[c]) ** 2 for c in add)
        with_it = sum((test_count[c] + n - target[c]) ** 2 for c, n in add.items())
        if with_it < without:
            test_keys.add(key)
            test_count += add
    split = {"dev": [], "test": []}
    for a in sorted(alerts, key=lambda a: a["id"]):
        split["test" if group_key(a) in test_keys else "dev"].append(a["id"])
    return split


if __name__ == "__main__":
    cfg = load_config()
    parts = sorted((ROOT / "data/parts").glob("*.jsonl"))
    alerts = [a for p in parts for a in read_jsonl(p) if a["label"]]   # unlabelled lab alerts wait
    write_jsonl(ROOT / cfg["paths"]["alerts"], alerts)
    splits = make_splits(alerts, cfg["data"]["test_fraction"], cfg["seed"])
    (ROOT / cfg["paths"]["splits"]).write_text(json.dumps(splits, indent=1) + "\n", encoding="utf-8")
    by_id = {a["id"]: a for a in alerts}
    for name, ids in splits.items():
        print(name, len(ids), dict(Counter((by_id[i]["provenance"], by_id[i]["label"]) for i in ids)))
