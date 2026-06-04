from __future__ import annotations

import asyncio
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional


def _strip_markup(text: str) -> str:
    return re.sub(r"\[/?[^\]]+\]", "", text)


class Reporter:
    def __init__(self, output_dir: str = "~/Desktop") -> None:
        self.output_dir = Path(output_dir).expanduser()

    async def generate(self, session_data: List[dict], name: Optional[str] = None) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._write, session_data, name)

    def _write(self, session_data: List[dict], name: Optional[str]) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r"[^a-z0-9_-]", "_", (name or "session").lower())
        filepath = self.output_dir / f"cyberpartner_{slug}_{ts}.md"

        filepath.write_text(self._build(session_data))
        return str(filepath)

    def _build(self, session_data: List[dict]) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = [
            "# CyberPartner Security Report",
            f"",
            f"**Generated:** {ts}  ",
            f"**Tool:** CyberPartner v1.0 (Claude AI + nmap)  ",
            f"**Disclaimer:** For authorized security testing only.  ",
            "",
            "---",
            "",
        ]

        for i, item in enumerate(session_data, 1):
            target = item.get("target") or item.get("domain") or "N/A"
            parts.append(f"## {i}. {item['type'].upper()} — {target}")
            parts.append("")

            if item["type"] == "scan":
                raw = item.get("data", "")
                clean = _strip_markup(raw)
                parts.append("```")
                parts.append(clean[:3000])
                parts.append("```")

                data = item.get("ports_summary")
                if data:
                    parts.append(f"**Open ports:** {data}")

            elif item["type"] == "email":
                data = item.get("data", {})
                if data.get("pattern"):
                    parts.append(f"**Email pattern:** `{data['pattern']}@{target}`")
                emails = data.get("emails", [])
                if emails:
                    parts.append("")
                    parts.append("**Candidates:**")
                    for e in emails[:8]:
                        parts.append(f"- `{e}`")

            elif item["type"] == "recon":
                data = item.get("data", {})
                if data.get("ip"):
                    parts.append(f"**IP:** `{data['ip']}`")
                if data.get("mx_records"):
                    parts.append(f"**MX:** {', '.join(data['mx_records'][:3])}")
                if data.get("subdomains"):
                    subs = ", ".join(f"`{s}`" for s in data["subdomains"][:6])
                    parts.append(f"**Subdomains:** {subs}")

            elif item["type"] == "ai_analysis":
                parts.append(item.get("content", ""))

            parts.append("")

        parts += [
            "---",
            "",
            "*CyberPartner v1.0 — Local AI Security Assistant*  ",
            "*Built with Python, Textual, and Claude AI*",
        ]

        return "\n".join(parts)
