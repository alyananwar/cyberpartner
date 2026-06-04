from __future__ import annotations

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanResult:
    target: str
    open_ports: List[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    formatted_lines: List[str] = field(default_factory=list)
    raw: str = ""
    error: Optional[str] = None


SCAN_FLAGS = {
    "quick":   ["-T4", "--top-ports", "1000", "-sV", "--version-intensity", "0"],
    "default": ["-T4", "-sV", "--top-ports", "1000"],
    "full":    ["-T4", "-sV", "-p-"],
    "vuln":    ["-T4", "--script", "vuln", "--top-ports", "100"],
    "ping":    ["-sn"],
}

PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "localhost")


class Scanner:
    def __init__(self) -> None:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True, timeout=5)
            self.available = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.available = False

    async def scan(self, target: str, scan_type: str = "default") -> ScanResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run, target, scan_type)

    def _run(self, target: str, scan_type: str) -> ScanResult:
        result = ScanResult(target=target)

        if not self.available:
            result.error = "nmap not found. Install: brew install nmap"
            result.formatted_lines = [
                "[red]nmap not installed.[/red]",
                "[dim]Install with: [cyan]brew install nmap[/cyan][/dim]",
                "",
                "[yellow]To scan without nmap, try:[/yellow]",
                "[dim]  nc -zv <host> 22 80 443 8080[/dim]",
            ]
            return result

        flags = SCAN_FLAGS.get(scan_type, SCAN_FLAGS["default"])
        is_private = any(target.startswith(p) for p in PRIVATE_PREFIXES)

        try:
            proc = subprocess.run(
                ["nmap"] + flags + [target],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return self._parse(target, proc.stdout, is_private)
        except subprocess.TimeoutExpired:
            result.error = "Scan timed out (120s)"
            result.formatted_lines = ["[red]Scan timed out after 120s[/red]"]
            return result
        except Exception as e:
            result.error = str(e)
            result.formatted_lines = [f"[red]Error: {e}[/red]"]
            return result

    def _parse(self, target: str, output: str, is_private: bool) -> ScanResult:
        result = ScanResult(target=target, raw=output)
        lines = []

        if not is_private:
            lines.append("[yellow]⚠ Non-private target. Confirm you have authorization.[/yellow]")
            lines.append("")

        lines.append(f"[bold green]Scan → {target}[/bold green]")
        lines.append("[dim]" + "─" * 55 + "[/dim]")

        for line in output.split("\n"):
            stripped = line.strip()
            port_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(.+)$", stripped)

            if port_match:
                port = int(port_match.group(1))
                proto = port_match.group(2)
                service = port_match.group(3).strip()
                result.open_ports.append(port)
                result.services[port] = service
                lines.append(
                    f"  [bold green]{port}/{proto}[/bold green]  "
                    f"[green]open[/green]  [cyan]{service}[/cyan]"
                )
            elif stripped.startswith("PORT") and "STATE" in stripped:
                lines.append(f"[bold dim]{stripped}[/bold dim]")
            elif stripped.startswith("Nmap scan report"):
                lines.append(f"[bold]{stripped}[/bold]")
            elif stripped.startswith("Host is up"):
                lines.append(f"[green]{stripped}[/green]")
            elif stripped.startswith("Nmap done"):
                lines.append(f"[dim]{stripped}[/dim]")
            elif stripped and not stripped.startswith("|"):
                lines.append(f"[dim]{stripped}[/dim]")
            elif stripped.startswith("|"):
                lines.append(f"[dim cyan]{stripped}[/dim cyan]")

        if not result.open_ports:
            lines.append("[dim]No open ports detected.[/dim]")

        result.formatted_lines = lines
        return result
