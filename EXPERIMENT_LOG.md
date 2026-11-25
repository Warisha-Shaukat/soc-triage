# EXPERIMENT_LOG

Append-only. Facts only: what was tried, what happened, what changed.

## 2026-11-25: environment check (section 2)

| Check | Result |
| --- | --- |
| OS | Windows 11 Home 10.0.26200 |
| CPU | Intel Core Ultra 7 255HX |
| RAM | 33,752,997,888 bytes total (about 31.4 GiB) |
| GPU | NVIDIA GeForce RTX 5060 Laptop GPU, 8151 MiB total, 7810 MiB free, driver 577.05 |
| `python --version` | 3.12.1 |
| `ollama --version` | FAILED: command not found (not installed) |
| `ollama list` | FAILED: command not found |
| `make` | FAILED: command not found |
| `gh` | FAILED: command not found |
| Network | available |

No model has been pulled or run.

## 2026-11-25: model tags verified against the Ollama registry

Read from `registry.ollama.ai` manifests. Size is the sum of layer sizes.

| Tag | Manifest sha256 prefix | Size |
| --- | --- | --- |
| `qwen3:8b` | 500a1f067a9f | 5.23 GB |
| `qwen3:8b-q4_K_M` | 500a1f067a9f (same as `qwen3:8b`) | 5.23 GB |
| `llama3.1:8b` | 46e0c10c039e | 4.92 GB |
| `llama3.1:8b-instruct-q4_K_M` | 46e0c10c039e (same as `llama3.1:8b`) | 4.92 GB |

The explicit quantization tags are proposed, because the short ones are aliases.
Ollama docs confirm `format` accepts a JSON schema and `think: false` is a chat parameter.
Whether `think: false` works together with `format` on Qwen3 is NOT tested yet.

## 2026-11-25: public dataset metadata (files not downloaded yet)

**AIT-ADS (Zenodo 8263181, version 1).** License CC-BY-4.0. `ait_ads.zip` is 96,202,946 bytes;
`labels.csv` is 3,703 bytes. Observations from the Zenodo page, the labels file head and the GitHub README:
- `<scenario>_wazuh.json` mixes Wazuh and Suricata alerts (README: Wazuh collected Suricata's alerts).
  The loader must filter to Wazuh's own rules.
- `labels.csv` holds attack-phase start and end times per scenario, **not a label per alert**. A benign
  alert that happens to fire during an attack window gets an attack label under the time rule.
  The README's per-event labels need the AIT-LDSv2 logs, which are a separate dataset.
- The publishers call the alerts synthetic (generated in a testbed). They are `provenance: public`
  here, but must not be described as production alerts.

**Hugging Face `kholil-lil/wazuh-alerts`** (sha 13cc552c9de4). Card states MIT. The first rows seen have
`input` as raw Wazuh JSON in a string and `output` as "False Positive"; agent fields are masked as `xxx`.
How the author assigned labels is NOT established. `wy777/wazuh-alerts` exists with the same card overview.

**Open risk.** Splitting by `rule.id` while stratifying by label only works if rules carry mixed labels.
If a rule is almost always one label, few rules decide the split balance. To measure once data is present.

## 2026-11-25: approvals and installs

- The author approved `config.yaml` and both models, a private GitHub repo, installing `gh` and Ollama,
  and the AIT-ADS download. The author also asked the agent to decide the labeling. `data/labeling_rule.md`
  is therefore agent-drafted. The 30-label hand spot-check has NOT been done.
- Config added after that approval: `ollama.seed`, `num_predict` 400 -> 512, `guard.unguarded_max_chars`,
  and the `injection` block (fields, 40 tp + 10 fp base alerts per split). The author has not reviewed these.
- `gh` installed through winget.

## 2026-11-25: failures so far

- First AIT-ADS download aborted at 5,668,920 of 96,202,946 bytes: `curl: (56) schannel: server closed abruptly`.
  A resuming loop replaced it; its first attempt also stalled (`curl: (28) Operation too slow`) at 12,826,364 bytes.
- `pip install` of all dependencies did not finish within 10 minutes (slow network); it was left running.
- Three long shell heredocs failed with "unexpected EOF while looking for matching quote". Nothing was
  written. Cause not confirmed (only long commands failed). The files were created with an editor tool instead.

## 2026-11-25: AIT-ADS `fox` scenario profiled (from the partial download)

- 462,523 alerts in `fox_wazuh.json`. Rule 31101 (web 400 errors) is 380,062 of them, 375,428 inside the `dirb` window.
- Suricata alerts appear through two decoders: `json` (rule 86601) and `snort` (rules 20100, 20101, ...).
- 855 of 27,942 Dovecot login-success alerts fall inside attack windows, so a pure time-window label would
  call them attacks. Decision: the stricter rule in `data/labeling_rule.md`.
- This look covered all `fox` alerts before any dev/test split existed. It informed the loader and the
  labeling rule, not the prompt or the guard.

## 2026-11-25: detector behaviour on clean synthetic dev alerts

- 168 synthetic alerts generated (84 tp, 84 fp).
- With an interim synthetic-only split, the suspicion detector flagged 7 of 84 clean dev alerts: all from the
  encoded-PowerShell family (3 fp, 4 tp), by the base64 rule. Not tuned away: it is a real cost of that rule.

## 2026-11-25: tests

- 64 tests passed with the system Python 3.12.1, with `statsmodels` replaced by a stub because it was not
  installed yet; `test_clopper_pearson_known_value` was deselected for that reason. To be rerun in the venv.

## 2026-11-25: repo, dependencies, AIT-ADS

- Private repo `Warisha-Shaukat/soc-triage` created; the first device sign-in code expired unused, the second worked.
- AIT-ADS download completed on resume attempt 4. MD5 of both files matches Zenodo; `unzip -t` found no errors.
  sha256 `ait_ads.zip` 9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9.
- The eight `_wazuh.json` files hold 2,600,263 alerts = 2,293,628 (Wazuh) + 306,635 (Suricata) as published.
  The loader dropped 613,358 as Suricata, about twice the published number, consistent with each Suricata alert
  being ingested twice (decoders `json` and `snort`). Counts per scenario: `data/parts/public_report.json`.
- Two loader runs (system Python, venv) gave byte-identical `public.jsonl`: 240 alerts, 120 tp and 120 fp.
- Exact-text deduplication removes little, because log lines contain timestamps. Near-duplicates are limited by the
  per-rule cap (round-robin sampling) and by grouping the split on rule.id.
- Dependencies installed and pinned (`requirements.txt`). 65 tests passed in the venv with real `statsmodels`.

## 2026-11-25: FAILURE and fix: first dev/test split was lopsided

- First split: stratified by provenance and label only. Every public rule in dev had a single label, and every
  public rule carrying both labels was in test (rules 31101, 5402, 5502, 5501, 31122, 31509, 5403; also 5503, fp only).
  Cause: groups are placed biggest first, and mixed groups are bigger. Dev would have been solvable from rule.id.
- Found by reading rule/label counts per split before any model run. Public test alert text was not read for this.
- Fix: stratify on group type (tp, fp, mixed) too; regression test added (66 tests pass).
- New split: dev 209 (public 61 tp / 64 fp, synthetic 41 / 43), test 199 (public 59 / 56, synthetic 43 / 41).
- Consequence: while checking the first split, up to two log lines per (rule, label) of its dev part were printed.
  Some of those rules (9701, 9705, 31151, 31516, 31104, 5551, 5304) are now in test. The prompt and guard were
  written before that and not changed after.

## 2026-11-25: inferred attacker IP checked

- See the numbers in `data/labeling_rule.md`: the address is probably a shared gateway, but Wazuh alerts from it are
  almost all inside attack windows (2 to 116 outside, 5,189 to 426,943 inside, per scenario).

## 2026-11-25: baseline on dev is degenerate (no model run yet)

- `python -m src.evaluate` ran with 0 model runs and wrote 14 tables; model tables are empty.
- On dev (n=209), the F1-optimal threshold is level >= 1, the same as always escalating: recall 100.0%,
  accuracy 48.8%, F1 65.6%. Best accuracy is at level >= 4: recall 67.6%, precision 55.2%, accuracy 57.4%.
- Likely causes, both choices made in this repo: the synthetic generator decouples level from label on purpose,
  and round-robin sampling over rules flattens AIT-ADS, where attack alerts are mostly a few web rules.
  So this baseline is weaker here than it may be on naturally distributed alerts.
- Objective left as specified (F1). Any change is an evaluation-design decision for the author.
- Test-split baseline rows exist in the generated table. Only dev rows were read when writing this entry.

## 2026-11-25: two evaluation changes approved by the author

- Second rules baseline: A1 = F1-optimal on dev (level >= 1), A2 = accuracy-optimal on dev (level >= 4).
- Harmless-text control: strategy `control`, wordings n1 and n2, planted exactly like the payloads.
  Injection cases are now 500 (dev) and 700 (test). Control rows are kept out of every ASR total.
- Both were decided before any model run. `src/evaluate.py` is tested on hand-made in-memory rows.
- The new evaluation test failed at first (IndexError in `table_conditions` for an empty split), and that commit
  was pushed with 1 of 68 tests failing. Fixed in the next commit; 68 pass.

## 2026-11-25: author review and spot-check sheet

- The author states having reviewed `data/labeling_rule.md` and the config additions.
- `python -m src.spotcheck make` wrote 42 alerts (32 public, 10 synthetic; 16/16 and 5/5 tp/fp; both splits):
  a blind sheet and a separate evidence file. The sheet is EMPTY; no label has been checked by hand yet.
- The sheet contains 20 test alerts. The check may change labels, but must not change prompt, guard or thresholds.
