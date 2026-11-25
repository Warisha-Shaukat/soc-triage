# Labeling rule

**Authorship note.** Section 9 of `AGENTS.md` reserves this file for the author. On 2026-11-25 the author
asked the coding agent (Claude Code) to choose the labeling. This text is therefore the agent's draft,
for the author to review. **The 30-label spot-check by hand has not been done.** No claim of human label
verification may be made until it is.

## What the labels mean

- `tp`: the event is part of attacker activity; an analyst should look at it.
- `fp`: the event is normal activity; dismissing it costs nothing.

## AIT-ADS (provenance `public`)

**The publishers' definition.** `labels.csv` gives start and end times of attack phases per scenario.
An alert inside a window gets that phase as its time label; an alert outside gets `false_positive`.

**Why that is not used as is.** Background activity continues during attacks. In the `fox` scenario,
855 Dovecot login-success alerts fall inside attack windows, out of 27,942. Most of these are presumably ordinary mail logins.

**Rule used here** (implemented in `src/load_public.py`):

| Label | Condition |
| --- | --- |
| `tp` | inside an attack window AND the source IP is the scenario's attacker |
| `tp` | inside the `privilege_escalation` window AND the decoder is `su`, `sudo` or `pam` (these logs carry no attacker IP) |
| `fp` | at least 1 hour away from every attack window, and not from the attacker IP |
| excluded | everything else |

The attacker IP is the source of at least 95% of web access alerts in the `dirb` window of that scenario.
If no IP reaches 95%, IP-based `tp` labels are not assigned in that scenario.

Suricata alerts are dropped. Alerts with the same rule ID and exact same log text are kept once.

**Known weaknesses.**
- The attacker IP is inferred, not published as a label, and it is probably not the attacker's alone. Across the
  eight scenarios the same address is the source of 1,948 to 39,468 Suricata alerts outside all attack windows
  (package updates, TLS noise), which suggests a shared gateway. Among the Wazuh alerts actually used it is far
  cleaner: 2 to 116 alerts outside windows per scenario, against 5,189 to 426,943 inside. A few benign alerts
  through that address can still carry a `tp` label, most likely for rare rules.
- The rule finds loud attack steps more easily than quiet ones, so `tp` is dominated by web scanning.
- A `su`/`sudo`/`pam` alert during the short privilege-escalation window could still be benign.
- `fp` means "no labeled attack was running", not "a person checked it".
- Excluding ambiguous alerts makes the task easier than real triage.

## Synthetic (provenance `synthetic`)

The label is the branch of the generator that made the alert (`src/gen_synthetic.py`). It is not a model's
opinion. The same project wrote the generator, the prompt and the guard, so synthetic scores may be optimistic.

## Lab (provenance `lab`)

None yet. The author would label these by hand.
