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
