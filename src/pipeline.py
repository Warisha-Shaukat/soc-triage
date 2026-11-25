"""alert -> guard -> model -> guard -> verdict, plus the runner that saves raw outputs.

    python -m src.pipeline --split dev --set clean  --guard off
    python -m src.pipeline --split dev --set inject --guard on --model secondary

Each run writes results/raw/<run_id>.jsonl (one line per alert, raw model text
included) and results/raw/<run_id>.meta.json. Tables are built later by
src/evaluate.py, which never calls a model.
"""
import argparse
import json

from . import guard
from .common import ROOT, git_commit, load_config, now_utc, read_jsonl, sha256_text
from .llm import OllamaClient

NO_LAYERS = {name: False for name in guard.ALL_LAYERS}


def build_system_prompt(layers: dict) -> str:
    """The guard notice is part of layer 3, so unguarded runs do not get it."""
    text = (ROOT / "prompts/triage_system.txt").read_text(encoding="utf-8")
    if layers.get("data_separation"):
        text += (ROOT / "prompts/triage_guard_addendum.txt").read_text(encoding="utf-8")
    return text


def triage_alert(wazuh: dict, client, cfg: dict, layers: dict) -> dict:
    """Run one alert through the pipeline. Returns everything needed for later analysis."""
    guarded = guard.prepare(wazuh, cfg["guard"], layers)
    user = "Alert fields:\n" + guard.wrap_fields(guarded.fields, guarded.nonce)
    result = client.triage(build_system_prompt(layers), user, guarded.nonce)

    if result.verdict is None:                       # still invalid after one retry
        final, reasons = "needs_human", ["invalid_output"]
    else:
        evidence = [e.model_dump() for e in result.verdict.evidence]
        final, reasons = guard.finalize(result.verdict.verdict, evidence, guarded, layers)
    return {
        "model_verdict": result.verdict.verdict if result.verdict else None,
        "final_verdict": final,
        "reasons": reasons,
        "guard_flags": guarded.flags,
        "truncated": guarded.truncated,
        "rationale": result.verdict.rationale if result.verdict else None,
        "invalid_error": result.error,
        "raw": result.raw,
        "latency_s": round(result.latency_s, 3),
        "cached": result.cached,
    }


def load_items(cfg: dict, split: str, which: str) -> list[dict]:
    """Rows with the same keys for the clean and the injection set."""
    ids = set(json.loads((ROOT / cfg["paths"]["splits"]).read_text(encoding="utf-8"))[split])
    alerts = [a for a in read_jsonl(ROOT / cfg["paths"]["alerts"]) if a["id"] in ids]
    if which == "clean":
        return [{"id": a["id"], "base_id": a["id"], "label": a["label"],
                 "provenance": a["provenance"], "wazuh": a["wazuh"]} for a in alerts]
    provenance = {a["id"]: a["provenance"] for a in alerts}
    return [{"id": c["id"], "base_id": c["base_id"], "label": c["base_label"],
             "provenance": provenance[c["base_id"]], "strategy": c["strategy"], "variant": c["variant"],
             "field": c["field"], "canary": c["canary"], "wazuh": c["wazuh"]}
            for c in read_jsonl(ROOT / cfg["paths"]["injection_set"]) if c["base_id"] in ids]


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test"], required=True)
    ap.add_argument("--set", choices=["clean", "inject"], required=True, dest="which")
    ap.add_argument("--guard", choices=["on", "off"], required=True)
    ap.add_argument("--model", choices=["primary", "secondary"], default="primary")
    ap.add_argument("--limit", type=int, help="smoke runs only; never for reported results")
    ap.add_argument("--rerun", action="store_true", help="allow replacing a finished run")
    args = ap.parse_args()

    layers = dict(cfg["guard"]["layers"]) if args.guard == "on" else NO_LAYERS
    run_id = f"{args.split}_{args.which}_guard-{args.guard}_{args.model}"
    if args.limit:
        run_id = "smoke_" + run_id
    out = ROOT / cfg["paths"]["results_raw"] / f"{run_id}.jsonl"
    meta_file = out.with_suffix(".meta.json")
    # Test-set discipline: a finished test run is never silently replaced.
    if meta_file.exists() and not (args.rerun or args.limit):
        raise SystemExit(f"{run_id} is already finished. Use --rerun and log the reason.")

    client = OllamaClient(cfg["models"][args.model]["tag"], cfg["ollama"], ROOT / cfg["paths"]["cache"])
    meta = {
        "run_id": run_id, "split": args.split, "set": args.which, "guard": args.guard, "layers": layers,
        "model_role": args.model, "model_tag": client.model, "model_digest": client.digest(),
        "ollama_version": client.version(), "ollama_options": cfg["ollama"],
        "prompt_sha256": sha256_text(build_system_prompt(layers)),
        "alerts_sha256": sha256_text((ROOT / cfg["paths"]["alerts"]).read_text(encoding="utf-8")),
        "git_commit": git_commit(), "started": now_utc(),
    }
    items = load_items(cfg, args.split, args.which)[:args.limit]
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for i, item in enumerate(items, 1):
            row = {k: v for k, v in item.items() if k != "wazuh"}
            row.update(triage_alert(item["wazuh"], client, cfg, layers))
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            if i % 25 == 0 or i == len(items):
                f.flush()
                print(f"{run_id}: {i}/{len(items)}", flush=True)
    meta.update(finished=now_utc(), n=len(items))
    meta_file.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
