"""Condition A: escalate when rule.level >= N. N is chosen on dev only."""
from .common import get_path
from .metrics import confusion, scores


def escalate(alert: dict, threshold: int) -> bool:
    return int(get_path(alert["wazuh"], "rule.level") or 0) >= threshold


def sweep(dev_alerts: list[dict], levels: list[int]) -> list[dict]:
    labels = [a["label"] for a in dev_alerts]
    return [{"threshold": n, **scores(confusion(labels, [escalate(a, n) for a in dev_alerts]))}
            for n in levels]


def choose_threshold(table: list[dict], objective: str = "f1") -> int:
    """Best score; ties go to the LOWER threshold, which misses fewer attacks."""
    return max(table, key=lambda r: (r[objective] or 0.0, -r["threshold"]))["threshold"]
