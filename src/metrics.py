"""Metrics and statistics. Positive class = real attack (tp). Positive decision = escalate."""
from dataclasses import dataclass

from scipy.stats import binomtest
from statsmodels.stats.proportion import proportion_confint


@dataclass
class Confusion:
    tp: int = 0   # attack, escalated
    fn: int = 0   # attack, dismissed   <- the costly error
    fp: int = 0   # benign, escalated   <- analyst time
    tn: int = 0   # benign, dismissed

    @property
    def n(self):
        return self.tp + self.fn + self.fp + self.tn


def confusion(labels: list[str], escalated: list[bool]) -> Confusion:
    c = Confusion()
    for label, esc in zip(labels, escalated, strict=True):
        if label == "tp":
            c.tp, c.fn = c.tp + bool(esc), c.fn + (not esc)
        else:
            c.fp, c.tn = c.fp + bool(esc), c.tn + (not esc)
    return c


def ratio(a, b):
    return a / b if b else None      # None = undefined; tables print an empty cell


def scores(c: Confusion) -> dict:
    return {
        "n": c.n,
        "accuracy": ratio(c.tp + c.tn, c.n),
        "recall_tp": ratio(c.tp, c.tp + c.fn),
        "precision": ratio(c.tp, c.tp + c.fp),
        "f1": ratio(2 * c.tp, 2 * c.tp + c.fp + c.fn),
        "escalation_rate": ratio(c.tp + c.fp, c.n),
    }


def exact_ci(k: int, n: int):
    """Clopper-Pearson 95% interval."""
    if n == 0:
        return None, None
    low, high = proportion_confint(k, n, alpha=0.05, method="beta")
    return float(low), float(high)


def wilson_ci(k: int, n: int):
    if n == 0:
        return None, None
    low, high = proportion_confint(k, n, alpha=0.05, method="wilson")
    return float(low), float(high)


def mcnemar_exact(correct_a: list[bool], correct_b: list[bool]) -> dict:
    """Paired comparison. Only discordant pairs matter: under H0 each one is a fair coin flip."""
    pairs = list(zip(correct_a, correct_b, strict=True))
    a_only = sum(1 for a, b in pairs if a and not b)
    b_only = sum(1 for a, b in pairs if b and not a)
    n = a_only + b_only
    p = binomtest(min(a_only, b_only), n, 0.5).pvalue if n else 1.0
    return {"n": len(pairs), "a_only": a_only, "b_only": b_only, "p": float(p),
            "diff": ratio(b_only - a_only, len(pairs))}     # effect size: accuracy(b) - accuracy(a)
