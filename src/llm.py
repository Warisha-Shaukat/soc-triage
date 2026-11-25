"""Ollama chat client: JSON-schema output, one retry, disk cache."""
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from pydantic import ValidationError

from .common import sha256_text
from .schema import Verdict


@dataclass
class LLMResult:
    verdict: Optional[Verdict]                         # None means invalid output
    raw: list[str] = field(default_factory=list)       # every attempt, exactly as returned
    latency_s: float = 0.0                             # wall clock of all attempts
    cached: bool = False
    error: Optional[str] = None


class OllamaClient:
    def __init__(self, model: str, cfg: dict, cache_dir):
        self.model, self.cfg = model, cfg
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def version(self) -> str:
        return requests.get(self.cfg["url"] + "/api/version", timeout=10).json()["version"]

    def digest(self) -> str:
        """Short id of the pulled model, as in `ollama list`."""
        models = requests.get(self.cfg["url"] + "/api/tags", timeout=10).json()["models"]
        return next((m["digest"][:12] for m in models if m["name"] == self.model), "not found")

    def _options(self) -> dict:
        return {k: self.cfg[k] for k in ("temperature", "num_ctx", "num_predict", "seed")}

    def _call(self, system: str, user: str) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": Verdict.model_json_schema(),
            "stream": False,
            "think": self.cfg["think"],
            "options": self._options(),
        }
        reply = requests.post(self.cfg["url"] + "/api/chat", json=body, timeout=self.cfg["timeout_s"])
        reply.raise_for_status()      # a server failure must stop the run, not count as a model answer
        return reply.json()["message"]["content"]

    def triage(self, system: str, user: str, nonce: Optional[str] = None) -> LLMResult:
        # The nonce is random per request. It is replaced in the cache key, otherwise the same
        # alert would never hit the cache. The saved answer still comes from a real nonce.
        key_text = user.replace(nonce, "NONCE") if nonce else user
        settings = json.dumps({**self._options(), "think": self.cfg["think"]}, sort_keys=True)
        schema = json.dumps(Verdict.model_json_schema(), sort_keys=True)
        key = sha256_text("\x00".join([self.model, settings, schema, system, key_text]))
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            saved = json.loads(cache_file.read_text(encoding="utf-8"))
            return self._parse(saved["raw"], saved["latency_s"], cached=True)

        raw, start = [], time.perf_counter()
        for _ in range(2):                               # first try + one retry
            raw.append(self._call(system, user))
            if self._validate(raw[-1])[0] is not None:
                break
        latency = time.perf_counter() - start
        cache_file.write_text(json.dumps({"raw": raw, "latency_s": latency}), encoding="utf-8")
        return self._parse(raw, latency, cached=False)

    @staticmethod
    def _validate(text: str):
        try:
            return Verdict.model_validate_json(text), None
        except ValidationError as e:
            return None, str(e.errors()[0]["msg"])

    def _parse(self, raw: list[str], latency: float, cached: bool) -> LLMResult:
        verdict, error = self._validate(raw[-1])
        return LLMResult(verdict, raw, latency, cached, error)
