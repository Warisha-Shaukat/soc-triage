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
