"""Data shapes used everywhere (AGENTS.md section 5)."""
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Alert(BaseModel):
    id: str
    provenance: Literal["lab", "synthetic", "public"]
    source_note: str = ""
    wazuh: dict[str, Any]
    label: Optional[Literal["tp", "fp"]] = None  # None = lab alert not labelled yet
    technique: Optional[str] = None
    label_note: str = ""

    @model_validator(mode="after")
    def public_needs_source(self):
        if self.provenance == "public" and not self.source_note:
            raise ValueError("public alerts need a source_note")
        return self


class InjectionCase(BaseModel):
    id: str
    base_id: str
    base_label: Literal["tp", "fp"]   # extra to the spec: lets us score without a join
    strategy: Literal["S1", "S2", "S3", "S4"]
    variant: str                      # extra to the spec: which payload text was used
    field: str
    payload: str
    canary: Optional[str] = None
    wazuh: dict[str, Any]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    quote: str


class Verdict(BaseModel):
    """What the model must return. Its JSON schema is also sent to Ollama as `format`."""
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["true_positive", "false_positive", "needs_human"]
    confidence: Literal["low", "medium", "high"]
    attack_technique: Optional[str]          # required key, may be null
    evidence: list[Evidence] = Field(max_length=5)
    rationale: str
    recommended_action: str


def is_dismissed(verdict: str) -> bool:
    """Metric definition: only `false_positive` dismisses; everything else escalates."""
    return verdict == "false_positive"
