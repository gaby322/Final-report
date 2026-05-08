from __future__ import annotations


import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    backend: str = "openai_compatible"
    model_name: str = "llama-3-1-8b-instruct"
    max_new_tokens: int = 1024
    temperature: float = 0.0
    api_base: Optional[str] = "http://localhost:11434/v1"
    api_key: Optional[str] = None


@dataclass
class LLMResponse:
    raw_text: str
    parsed_json: Optional[Dict[str, Any]]
    parse_success: bool
    backend_used: str
    tokens_used: Optional[int] = None


class LLMAdapter:
    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()

    def call(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        backend = self.config.backend
        if backend == "openai_compatible":
            return self._call_openai_compatible(system_prompt, user_prompt)
        if backend == "none":
            return self._call_none(system_prompt, user_prompt)
        raise ValueError(f"Unknown LLM backend: {backend}")

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import httpx

        if not self.config.api_base:
            raw_text = '{"error": "openai_compatible backend requires api_base"}'
            parsed, success = self._parse_json(raw_text)
            return LLMResponse(
                raw_text=raw_text,
                parsed_json=parsed,
                parse_success=success,
                backend_used=self.config.model_name,
                tokens_used=None,
            )

        payload = {
            "model": self.config.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.config.max_new_tokens,
            "temperature": self.config.temperature,
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        try:
            resp = httpx.post(
                f"{self.config.api_base}/chat/completions",
                json=payload,
                headers=headers,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens")
        except Exception as e:
            raw_text = f'{{"error": "API call failed: {e}"}}'
            tokens = None

        parsed, success = self._parse_json(raw_text)
        return LLMResponse(
            raw_text=raw_text,
            parsed_json=parsed,
            parse_success=success,
            backend_used=self.config.model_name,
            tokens_used=tokens,
        )

    def _call_none(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        return LLMResponse(
            raw_text="",
            parsed_json=None,
            parse_success=False,
            backend_used="none",
        )

    @staticmethod
    def _parse_json(text: str) -> tuple[Optional[Dict[str, Any]], bool]:
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
        text = text.strip()


        try:
            return json.loads(text), True
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()

            for i, ch in enumerate(text):
                if ch != "{":
                    continue
                try:
                    obj, _ = decoder.raw_decode(text[i:])
                    if isinstance(obj, dict):
                        return obj, True
                except json.JSONDecodeError:
                    continue

        return None, False
