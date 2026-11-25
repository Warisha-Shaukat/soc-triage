"""The guard (AGENTS.md section 6). Five layers, each with its own switch.

Layers 1-3 clean the input before the model sees it. Layers 4-5 decide what
to do with the model's answer. The important property is *fail-closed*: if we
suspect injection, the alert can never be dismissed.

A limitation to remember: layer 5 is a list of patterns written by the same
project that writes the attacks. It shows what pattern matching costs and
catches, not that the guard resists an adaptive attacker.
"""
import base64
import binascii
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Optional

from .common import get_path

ALL_LAYERS = ("field_selection", "normalization", "data_separation",
              "evidence_grounding", "suspicion_detector")


@dataclass
class GuardedInput:
    fields: dict[str, str]                              # exactly what the model sees, per field
    flags: list[str] = field(default_factory=list)      # detector hits (layer 5)
    truncated: list[str] = field(default_factory=list)  # fields that were cut (layer 1)
    nonce: Optional[str] = None                         # set when layer 3 is on


def to_text(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


# --- Layer 1: field selection and truncation -------------------------------
def select_fields(alert: dict, allowed: list[str], max_chars: int):
    fields, truncated = {}, []
    for name in allowed:
        value = get_path(alert, name)
        if value in (None, "", []):
            continue
        text = to_text(value)
        if len(text) > max_chars:
            text = text[:max_chars] + "[TRUNCATED]"
            truncated.append(name)
        fields[name] = text
    return fields, truncated


# --- Layer 2: normalization ------------------------------------------------
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# C0 controls, DEL, C1 controls, zero-width and bidirectional-override characters.
CONTROL = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\ufeff]")
ROLE = re.compile(r"\b(system|assistant|user|developer)\s*:", re.I)
ANNOTATION = re.compile(r"\[\s*/?\s*(soc|admin|analyst|system|inst|note)[^\]]{0,40}\]", re.I)


def normalize(text: str) -> str:
    text = ANSI.sub("", text)
    text = CONTROL.sub(" ", text)
    # Look-alike angle quotes: no more tags, no more <|special tokens|>.
    text = text.replace("<", "‹").replace(">", "›")
    text = ROLE.sub(lambda m: m.group(1) + " -", text)                    # "system:" -> "system -"
    text = ANNOTATION.sub(lambda m: "(" + m.group(0)[1:-1] + ")", text)   # "[SOC ADMIN]" -> "(SOC ADMIN)"
    return text.replace("```", "'''")


# --- Layer 3: data/instruction separation ----------------------------------
def new_nonce(n_bytes: int = 8) -> str:
    return secrets.token_hex(n_bytes)


def wrap_fields(fields: dict[str, str], nonce: Optional[str]) -> str:
    """With a nonce, an attacker cannot guess the closing delimiter."""
    if nonce is None:
        return "\n".join(f"{name}: {text}" for name, text in fields.items())
    return "\n".join(f"<<DATA {nonce} {name}>>\n{text}\n<<END {nonce}>>"
                     for name, text in fields.items())


# --- Layer 4: evidence grounding -------------------------------------------
def ungrounded_quotes(evidence: list[dict], fields: dict[str, str]) -> list[str]:
    """Quotes that are not an exact substring of the field they name.

    Compared with the text the model was shown (after cleaning), because it
    cannot quote text it never saw. An empty quote counts as ungrounded:
    "" is a substring of everything and would pass for free.
    """
    return [e["quote"] for e in evidence
            if not e["quote"].strip() or e["quote"] not in fields.get(e["field"], "")]


# --- Layer 5: suspicion detector -------------------------------------------
PATTERNS = {
    "override": re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your|the)\b"
        r".{0,30}\b(instruction|prompt|rule|guideline|direction|context)s?", re.I),
    "verdict_instruction": re.compile(
        r"\b(classify|mark|label|treat|report|set|return|output|respond|answer|conclude)\b.{0,60}"
        r"\b(benign|false[_ -]?positive|true[_ -]?positive|harmless|not malicious|verdict|safe)\b", re.I),
    "authority_claim": re.compile(
        r"\b(white-?list(ed)?|allow-?list(ed)?|pre-?approved|authori[sz]ed (by|test|pentest|scan|activity)|"
        r"approved by|cleared by|verified by|on behalf of)\b", re.I),
    "addressed_to_model": re.compile(
        r"\b(you are (now|an?|the)|as an ai|language model|llm|dear analyst|"
        r"note to (the )?(analyst|model|ai)|triage (model|system|assistant|bot))\b", re.I),
    "canary_request": re.compile(
        r"\b(include|write|say|print|mention|add)\b.{0,30}\b(word|token|phrase)\b", re.I),
    "structural_mimicry": re.compile(
        r"</?\s*(log|data|alert|system|instruction|context)s?\s*>|<\|[a-z_]+\|>|<<\s*(END|DATA)|"
        r"\[\s*/?\s*(soc|admin|analyst|system|inst)\b[^\]]{0,40}\]|"
        r"\b(system|assistant)\s*:|\"verdict\"\s*:|\bfinal (verdict|answer)\b|```", re.I),
}
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def decodes_to_text(blob: str) -> bool:
    """True if a blob is base64 of readable text. Hex hashes and paths usually decode to noise."""
    for encoding in ("utf-8", "utf-16-le"):              # PowerShell -enc uses UTF-16LE
        try:
            text = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode(encoding)
        except (binascii.Error, ValueError):
            continue
        if text and all(c.isascii() and (c.isprintable() or c in "\r\n\t") for c in text):
            return True
    return False


def detect_suspicion(texts: dict[str, str]) -> list[str]:
    """Returns flags such as 'override@data.url'."""
    flags = []
    for name, text in texts.items():
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                flags.append(f"{label}@{name}")
        if any(decodes_to_text(b.rstrip("=")) for b in BASE64_BLOB.findall(text)):
            flags.append(f"encoded_text@{name}")
    return flags


# --- Putting the layers together -------------------------------------------
def prepare(alert: dict, cfg: dict, layers: dict[str, bool]) -> GuardedInput:
    """Everything that happens before the model call."""
    # Unguarded runs get the same field list (so B and E compare like with like) but no real
    # truncation, only a hard cap that keeps the prompt inside the context window.
    cap = cfg["max_field_chars"] if layers.get("field_selection") else cfg["unguarded_max_chars"]
    fields, truncated = select_fields(alert, cfg["allowed_fields"], cap)

    flags = []
    if layers.get("suspicion_detector"):
        # Look at the RAW allowed fields: cleaning removes the very tokens we search for,
        # and truncation could hide a payload sitting past the cut.
        raw, _ = select_fields(alert, cfg["allowed_fields"], 10**9)
        flags = detect_suspicion(raw)

    if layers.get("normalization"):
        fields = {name: normalize(text) for name, text in fields.items()}

    nonce = new_nonce(cfg["nonce_bytes"]) if layers.get("data_separation") else None
    return GuardedInput(fields, flags, truncated, nonce)


def finalize(model_verdict: str, evidence: list[dict], guarded: GuardedInput,
             layers: dict[str, bool]) -> tuple[str, list[str]]:
    """Everything that happens after the model call. Returns (final verdict, reasons)."""
    verdict, reasons = model_verdict, []
    if layers.get("evidence_grounding"):
        bad = ungrounded_quotes(evidence, guarded.fields)
        if bad:
            verdict = "needs_human"
            reasons.append(f"ungrounded_evidence({len(bad)})")
    if layers.get("suspicion_detector") and guarded.flags:
        verdict = "needs_human"                          # fail closed
        reasons.append("suspected_injection")
    return verdict, reasons
