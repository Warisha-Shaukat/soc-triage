# Local SOC Triage Assistant with a Log-Injection Guard

Research prototype. It measures whether attacker-controlled log text can steer small local LLMs
(8B, 4-bit, via Ollama) that triage Wazuh-format alerts, and what a fail-closed guard costs.

**Status: setup only. No results exist yet.** The configuration in `config.yaml` is a proposal
awaiting the author's approval. See `EXPERIMENT_LOG.md` for facts so far and `AGENTS.md` for the spec.
