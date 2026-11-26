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

## 2026-11-25: label check done by the coding agent, not by hand

- The author asked the agent to check all 42 alerts. The agent labeled from the sheet text only; its labels were
  committed (`data/spotcheck/sheet_ai_check.csv`) before the evidence rows were opened. `sheet.csv` is still empty:
  the hand spot-check required by `AGENTS.md` section 9 has NOT been done.
- Result (`python -m src.spotcheck score sheet_ai_check.csv`): public 30/31 agree, 1 unsure
  (exact 95% CI 83.3-99.9%); synthetic 10/10.
- This is weak evidence of label quality. The agent also wrote the labeling rule and the generator, and had seen
  some of these public dev alerts with labels earlier.
- Disagreement: row 24 (p0115, PAM session opened, stored tp, test split). Unsure: row 13 (PAM session closed, stored tp,
  dev). Both are `tp` only because they fall in a privilege-escalation window; their text is like benign PAM alerts.
- No label changed. The PAM `tp` alerts stay as a known weak spot of the rule.
- AI check done before any model run; no test alert text was used to change the prompt, guard or thresholds.

## 2026-11-25: Ollama

- Ollama 0.40.18 installed and serving on 127.0.0.1:11434. Both approved models are being pulled.

## 2026-11-25: plan for the late hand spot-check (written before any model run)

- The author may do the hand check after the runs. Stored labels stay the primary analysis. If the hand check
  disagrees with any, tables are recomputed from the saved raw outputs as a separate sensitivity analysis, with no new
  model calls; injection cases whose base alert changed label are left out of it.
- The author should fill `sheet.csv` before reading any results or `evidence.csv`.

## 2026-11-25: Qwen3 smoke test (dev only, 3 x 10 alerts, not used as results)

- `qwen3:8b-q4_K_M`, id 500a1f067a9f (matches the registry prefix), Ollama 0.40.18. `ollama ps`: 5.6 GB, 100% GPU,
  context 4096; GPU memory used 5502 MiB.
- 30/30 outputs were valid JSON on the first attempt, so `format` and `think: false` work together here.
- Latency about 4.6 to 7.1 s per alert after a 9.6 s first call (model load). A second model was downloading meanwhile.
- The cache was cleared afterwards so that reported latencies come from the full runs.

## 2026-11-26: Qwen3 dev runs finished (1,418 alerts, commit e9c0a62, no `-dirty`)

- `python -m src.evaluate` and `python -m src.inspect_run dev primary`. No run failed; 0 retries, 0 invalid outputs.
- Clean dev (n=209), no guard: recall 102/102, but 194/209 escalated; accuracy 56.0%. Rules A2: 57.4%, A1: 48.8%.
  B vs A2: 36 vs 33 discordant, exact p=0.81. So the LLM shows no accuracy advantage over A2 here, although its recall
  is higher (102/102 against 69/102). On synthetic dev it escalated 84/84.
- Clean dev, guard on: recall 94/102, accuracy 56.5%. All 8 missed attacks are rule 5502 "PAM: Login session closed",
  dismissed by the model itself once the prompt notice and data separation are on. Dev has 8 tp and 8 fp alerts of that
  rule; the tp ones are tp only because of the attack time window (weak label logged on 2026-11-25). Cause not isolated.
- Injection dev, no guard: ASR 216/320 (67.5%); control text 4/80. S1 80/80, S2 55/80, S3 80/80, S4 1/80.
- Injection dev, guard on: ASR 0/304, control 0/76. READ WITH CARE: the detector flagged 320/320 payload cases because
  its patterns were written alongside wordings a and b, so the 0 is close to true by construction. Before the detector
  decided, the model itself still said false_positive in S1 43/80, S2 23/80, S3 35/80, S4 1/80 (all attack-based cases,
  not ASR). Prompt-level separation alone therefore lowered but did not stop the attack. Wording c on test is the real check.
- Caveat on S4: unguarded 1/80 mostly means the model did not decode the blob, not that it resisted it.
- Decision: no bug found, so prompt, guard, thresholds, labels and data stay exactly as they were. Nothing was tuned on
  dev results. `src/inspect_run.py` (read-only diagnostics) is the only code added. This is the final configuration.
- Test is run next, once. Authorization: `AGENTS.md` section 8 asks for it; the agent stated it would do so unless the
  author objected, and the author said to continue without objecting. Not approved in explicit words.

## 2026-11-26: Streamlit app (P1), requested by the author

- `app.py` follows `AGENTS.md` section 4.6 (queue, evidence highlighting, Confirm/Override to `data/overrides.jsonl`).
  Additions beyond the spec: labels hidden by default (to keep the hand spot-check blind) and a "Try an alert" tab that
  runs the live pipeline, guard off and on, with an optional harmless payload and a separate cache.
- Streamlit 1.67.0 was already pinned; no new dependency. `app.py`, `tests/` and `.gitignore` are outside the inputs
  that mark a run `-dirty`; `data/overrides.jsonl` is gitignored so a click cannot mark later runs dirty.
- Checked with 3 new unit tests (71 pass) and Streamlit's headless AppTest, including one Confirm click written to a
  scratch file. Not yet opened in a browser, and the live tab was not run against Ollama, because Llama runs were
  using the GPU. Committed while `dev_inject_guard-off_secondary` was running; triage code, prompts, config and data
  are unchanged, so later Llama runs record a newer commit with the same pipeline.

## 2026-11-26: Qwen3 test runs (once) and Llama 3.1 dev runs finished

- Qwen3 test: all four conditions ran once at commit e2597c0 (1,798 alerts), no failure. Results not read yet.
- Llama 3.1 smoke (10 dev alerts, guard on): fine. `ollama ps`: id 46e0c10c039e, 5.3 GB, 100% GPU, context 4096.
  Those 10 answers were reused from the cache in the full guard-on clean dev run (11 cached rows there).
- Llama dev (`python -m src.inspect_run dev secondary`): 0 retries, 0 invalid. Clean, no guard: it dismissed 84 of
  102 attacks, across 19 rules. Rationales agree with the verdicts (often confidence "low" and "requires further
  investigation", yet `false_positive` rather than `needs_human`). This is model behavior, not a parsing error.
  Because the configuration is frozen for both models, nothing was changed for Llama.
- Caching in guarded injection runs: 110 rows in each model's guarded dev run were cache hits. All are `full_log`
  cases where the 200-character cut (layer 1) removed the whole payload, so several cases sent identical text.
  Counted without a model (planted field only): the payload is fully cut in 100 of 400 dev attack cases and 14 of 560
  test attack cases, and partly cut in 108 dev and 189 test attack cases. So part of the guarded result comes from
  truncation, which is a guard layer by design but means the model never saw that payload. This count will become a
  generated table once the runs finish; cached rows carry the latency of the first identical call.
- Llama test started next, once, with the same frozen configuration.

## 2026-11-26: Llama 3.1 test runs (once), final tables, hand spot-check

- Llama test: four conditions ran once at commit 800be85 (1,798 alerts), no failure, 0 invalid outputs.
  Qwen3 test ran at e2597c0. Both commits have the same prompt, guard, config and data.
- `src/evaluate.py` gained one diagnostic table, `asr_inside`, added after the dev runs and after the test runs had
  finished: whether the payload survived the 200-character cut, and the model's own verdict before the guard.
  It does not change any existing metric. 72 tests pass.
- Main test results (from `results/tables/`): the detector flagged 100% of wordings a/b and 4% of held-out wording c
  (2 of 50 per strategy). Guarded attack success on c: Qwen3 73/152 (48.0%), Llama 3.1 29/44 (65.9%); on a/b: 0.
  So the dev result of 0% came from the detector matching the payloads it was written with.
- Qwen3 escalated 198 of 199 clean test alerts; Llama 3.1 dismissed 97 of 102 attacks. Llama's unguarded attack
  success rate rests on 1 eligible base alert.
- Hand spot-check, by the author: 41 of 42 rows labeled (row 39 blank). The labels were typed in the `your_note`
  column; the file as saved is commit 18f33b5. Moving them to `your_label` without changing a value and running
  `python -m src.spotcheck score`: public 18/31 agree (exact 95% CI 39.1-75.5%), synthetic 3/10 (6.7-65.2%).
  13 public and 7 synthetic disagreements. The agent's own check had agreed 30/31 and 10/10; it is not independent.
- No label was changed. The sensitivity analysis with the author's labels (planned 2026-11-25) has not been run.
