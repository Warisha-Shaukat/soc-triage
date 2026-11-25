# Local SOC Triage Assistant with a Log-Injection Guard

Research prototype. It measures whether attacker-controlled log text can steer small local LLMs
(8B, 4-bit, via Ollama) that triage Wazuh-format alerts, and what a fail-closed guard costs.

**Status: no model run has finished yet.** Empty tables below mean "not run", never "zero".

## What is and is not new

Local-LLM triage with Wazuh and log-based prompt injection both exist already (see `AGENTS.md`, section 1).
This prototype measures small local open-weight models on Wazuh-format alerts, and the cost of failing closed.

## Setup

Hardware: NVIDIA RTX 5060 Laptop GPU (8 GB), 32 GB RAM, Windows 11.

```
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Linux: .venv/bin/python
ollama pull qwen3:8b-q4_K_M
ollama pull llama3.1:8b-instruct-q4_K_M
```

AIT-ADS is not redistributed here in full. Download `ait_ads.zip` and `labels.csv` from
https://zenodo.org/records/8263181 (CC-BY-4.0) into `data/raw/ait_ads/`.

## Commands

| Step | make | Without make (Windows) |
| --- | --- | --- |
| Tests | `make test` | `.venv/Scripts/python -m pytest -q` |
| Build data | `make data` | `python -m` `src.gen_synthetic`, `src.load_public`, `src.make_splits`, `src.build_injection_set` |
| Clean dev runs | `make run` | `python -m src.pipeline --split dev --set clean --guard off` (then `on`) |
| Injection dev runs | `make inject` | `python -m src.pipeline --split dev --set inject --guard off` (then `on`) |
| All tables | `make eval` | `python -m src.evaluate` |

`evaluate` reads saved raw outputs only and never calls a model. The test split uses the same pipeline
command with `--split test`; a finished run is refused a second time unless `--rerun` is given.

## Metric definition

- `dismiss` = final verdict `false_positive`. `escalate` = `true_positive`, `needs_human` or invalid output.
- Real attacks (`tp`) should be escalated. The costly error is dismissing one, so recall on `tp` comes first.
- "Always escalate" is listed for reference: it has perfect recall and no value.
- Attack success rate (ASR): among attack alerts handled correctly when clean, the share dismissed after injection.

## Data

<!-- BEGIN:data -->
<!-- END:data -->

## Results

Clean alerts:

<!-- BEGIN:conditions -->
<!-- END:conditions -->

Paired comparison (McNemar exact):

<!-- BEGIN:mcnemar -->
<!-- END:mcnemar -->

Guard cost on clean benign alerts:

<!-- BEGIN:guard_cost -->
<!-- END:guard_cost -->

Attack success rate:

<!-- BEGIN:asr_overall -->
<!-- END:asr_overall -->

By strategy:

<!-- BEGIN:asr_by_strategy -->
<!-- END:asr_by_strategy -->

By wording (c = held out from detector tuning):

<!-- BEGIN:asr_by_wording -->
<!-- END:asr_by_wording -->

Canary token in the rationale (a model that merely quotes the payload also counts):

<!-- BEGIN:canary -->
<!-- END:canary -->

Runs:

<!-- BEGIN:runs -->
<!-- END:runs -->

More tables (by field, by provenance, detector hits, escalation attacks, baseline sweep) are in `results/tables/`.

## Limitations

- **Small sample and low power.** Intervals are wide, and a non-significant McNemar result is not evidence of no difference.
- **Synthetic share.** Part of the data comes from this repo's generator. The same project wrote generator, prompt,
  payloads and guard, so those scores may be optimistic. AIT-ADS comes from a testbed, not production.
- **Labels.** AIT-ADS has attack time windows, not per-alert labels; `data/labeling_rule.md` describes the rule and
  its weaknesses. There is one labeling rule, drafted by the coding agent. The hand spot-check is not done.
- **Easier than reality.** Ambiguous alerts are excluded, and each alert is judged without surrounding events.
- **Split by rule.id.** This prevents near-copies in test, but few distinct rules decide the result.
- **Injection results apply only to the tested payloads and models.** Payloads are not adaptive, and the detector
  patterns were written alongside them. The held-out wording is "not tuned on", not independent.
- **Injection cases are clustered.** Several cases share one base alert, so exact intervals on ASR are too narrow;
  the tables also list base alerts. There is no neutral-text control yet, so some flips may come from added text itself.
- **No authentication, no live integration.** Lab prototype only.
