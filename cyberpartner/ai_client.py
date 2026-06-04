from __future__ import annotations

import asyncio
from typing import Optional

import anthropic

SYSTEM_PROMPT = """You are CyberPartner, a local AI-powered cybersecurity assistant.
You help with: pentesting methodology, scan result analysis, OSINT interpretation,
network security, vulnerability assessment, and defensive recommendations.

Be concise, technical, and practical. No fluff.
When analyzing scan results:
1. Call out critical open ports/services
2. Flag potential attack vectors
3. Suggest specific next steps
4. Note any misconfigurations

For email/OSINT queries: give actionable intel.
Keep responses under 200 words unless deep analysis is requested."""


class AIClient:
    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self._history: list[dict] = []

    async def ask(self, question: str, context: str = "") -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_ask, question, context)

    def _sync_ask(self, question: str, context: str) -> str:
        content = f"{context}\n\n{question}" if context else question
        self._history.append({"role": "user", "content": content})
        # keep last 20 messages to manage cost
        history = self._history[-20:]

        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=history,
            )
            reply = resp.content[0].text
            self._history.append({"role": "assistant", "content": reply})
            return reply
        except anthropic.APIError as e:
            return f"[API Error] {e}"
        except Exception as e:
            return f"[Error] {e}"

    def reset(self) -> None:
        self._history = []

    def set_model(self, model: str) -> None:
        self.model = model
