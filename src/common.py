"""Small helpers shared by the scripts."""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_config(path=None) -> dict:
    file = Path(path) if path else ROOT / "config.yaml"
    return yaml.safe_load(file.read_text(encoding="utf-8"))


def read_jsonl(path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path, rows) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_path(obj, dotted: str):
    """get_path(alert, "data.srcuser") -> the value, or None if any part is missing."""
    for part in dotted.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def set_path(obj: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    for part in parts[:-1]:
        obj = obj.setdefault(part, {})
    obj[parts[-1]] = value


def git_commit() -> str:
    """Commit id, plus '-dirty' if inputs differ from it. Result files do not count as dirty."""
    def run(*args):
        done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return done.stdout.strip()
    sha = run("rev-parse", "HEAD") or "unknown"
    dirty = run("status", "--porcelain", "--", "src", "prompts", "config.yaml", "data")
    return sha + ("-dirty" if dirty else "")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
