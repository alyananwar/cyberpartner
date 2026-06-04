from __future__ import annotations

import asyncio
import socket
import smtplib
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests


EMAIL_PATTERNS = [
    ("{first}.{last}", "first.last"),
    ("{f}{last}", "flast"),
    ("{first}", "first"),
    ("{f}.{last}", "f.last"),
    ("{first}_{last}", "first_last"),
    ("{first}{last}", "firstlast"),
    ("{last}.{first}", "last.first"),
]

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "vpn", "portal", "admin",
    "dev", "staging", "api", "app", "careers", "blog",
    "docs", "support", "auth", "sso",
]


@dataclass
class EmailResult:
    domain: str
    pattern: Optional[str] = None
    emails: List[str] = field(default_factory=list)
    formatted_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"domain": self.domain, "pattern": self.pattern, "emails": self.emails}


@dataclass
class ReconResult:
    domain: str
    ip: Optional[str] = None
    mx_records: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    formatted_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "mx_records": self.mx_records,
            "subdomains": self.subdomains,
        }


class Recon:
    def __init__(self, hunter_api_key: Optional[str] = None) -> None:
        self.hunter_key = hunter_api_key

    async def find_email_pattern(self, domain: str, name: Optional[str] = None) -> EmailResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._email, domain, name)

    def _email(self, domain: str, name: Optional[str]) -> EmailResult:
        result = EmailResult(domain=domain)
        lines: List[str] = []

        lines.append(f"[bold green]Email Pattern → {domain}[/bold green]")
        lines.append("[dim]" + "─" * 55 + "[/dim]")

        # Try Hunter.io
        if self.hunter_key:
            hunter = self._hunter(domain)
            if hunter:
                result.pattern = hunter.get("pattern")
                result.emails = hunter.get("emails", [])[:6]

                if result.pattern:
                    lines.append(
                        f"[green]Pattern (Hunter.io):[/green] "
                        f"[cyan]{result.pattern}@{domain}[/cyan]"
                    )

                if result.emails:
                    lines.append("")
                    lines.append("[bold]Emails on record:[/bold]")
                    for email in result.emails:
                        lines.append(f"  [cyan]{email}[/cyan]")
        else:
            lines.append("[dim]No Hunter.io key. Add HUNTER_API_KEY to .env for auto-detection.[/dim]")

        # Generate candidates if name provided
        if name:
            parts = name.strip().split()
            if len(parts) >= 2:
                first = parts[0].lower()
                last = parts[-1].lower()
                f = first[0]
                lines.append("")
                lines.append(f"[bold]Candidates for [cyan]{name}[/cyan]:[/bold]")

                best = None
                candidates: List[str] = []

                for pat_template, label in EMAIL_PATTERNS:
                    try:
                        addr = pat_template.format(first=first, last=last, f=f) + f"@{domain}"
                        candidates.append((addr, label))
                    except KeyError:
                        pass

                # If we know the pattern, promote the match
                if result.pattern:
                    try:
                        pat_clean = result.pattern.replace("{first}", first).replace(
                            "{last}", last).replace("{f}", f)
                        best = f"{pat_clean}@{domain}"
                        lines.append(
                            f"  [bold green]★ {best}[/bold green]  "
                            f"[dim](matches company pattern)[/dim]"
                        )
                    except Exception:
                        pass

                for addr, label in candidates[:6]:
                    if addr != best:
                        lines.append(f"  [cyan]{addr}[/cyan]  [dim]({label})[/dim]")

                if best:
                    result.emails.insert(0, best)
            else:
                lines.append("[yellow]Provide full name: email domain.com Firstname Lastname[/yellow]")

        if not name and not result.pattern:
            lines.append("")
            lines.append("[bold]Common patterns to try:[/bold]")
            for _, label in EMAIL_PATTERNS[:5]:
                lines.append(f"  [dim]{label}@{domain}[/dim]")
            lines.append("")
            lines.append("[dim]Usage: email <domain> <Firstname Lastname>[/dim]")

        result.formatted_lines = lines
        return result

    def _hunter(self, domain: str) -> Optional[Dict]:
        try:
            resp = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "api_key": self.hunter_key, "limit": 10},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "pattern": data.get("pattern"),
                    "emails": [e["value"] for e in data.get("emails", [])],
                }
        except Exception:
            pass
        return None

    async def run_recon(self, domain: str) -> ReconResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._recon, domain)

    def _recon(self, domain: str) -> ReconResult:
        result = ReconResult(domain=domain)
        lines: List[str] = []

        lines.append(f"[bold green]Recon → {domain}[/bold green]")
        lines.append("[dim]" + "─" * 55 + "[/dim]")

        # DNS
        try:
            result.ip = socket.gethostbyname(domain)
            lines.append(f"[green]IP Address:[/green]  {result.ip}")
        except socket.gaierror:
            lines.append("[red]DNS resolution failed[/red]")

        # MX
        mx = self._mx(domain)
        if mx:
            result.mx_records = mx
            lines.append("")
            lines.append("[bold]MX Records:[/bold]")
            for rec in mx[:4]:
                lines.append(f"  [cyan]{rec}[/cyan]")
            # Infer email provider
            if any("google" in r.lower() for r in mx):
                lines.append("  [dim]→ Google Workspace[/dim]")
            elif any("microsoft" in r.lower() or "outlook" in r.lower() for r in mx):
                lines.append("  [dim]→ Microsoft 365[/dim]")

        # Subdomains
        lines.append("")
        lines.append("[bold]Subdomain Probe:[/bold]")
        found: List[str] = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append(fqdn)
                lines.append(f"  [green]✓[/green] [cyan]{fqdn}[/cyan]  [dim]→ {ip}[/dim]")
            except socket.gaierror:
                pass

        if not found:
            lines.append("  [dim]No common subdomains resolved[/dim]")

        result.subdomains = found

        # Cert transparency via crt.sh (free, no key)
        certs = self._crtsh(domain)
        if certs:
            lines.append("")
            lines.append("[bold]Cert Transparency (crt.sh):[/bold]")
            for sub in certs[:8]:
                if sub not in found:
                    lines.append(f"  [dim]{sub}[/dim]")

        lines.append("")
        lines.append(f"[dim]Tip: run [cyan]email {domain} <Name>[/cyan] for email patterns[/dim]")
        if result.ip:
            lines.append(f"[dim]Tip: run [cyan]scan {result.ip}[/cyan] to scan open ports[/dim]")

        result.formatted_lines = lines
        return result

    def _mx(self, domain: str) -> List[str]:
        try:
            proc = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=5,
            )
            return [l.strip() for l in proc.stdout.split("\n") if l.strip()][:5]
        except Exception:
            return []

    def _crtsh(self, domain: str) -> List[str]:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=8,
                headers={"User-Agent": "CyberPartner/1.0"},
            )
            if resp.status_code == 200:
                entries = resp.json()
                subs = set()
                for e in entries[:50]:
                    name = e.get("name_value", "")
                    for s in name.split("\n"):
                        s = s.strip().lstrip("*.")
                        if s and s.endswith(domain) and s != domain:
                            subs.add(s)
                return sorted(subs)[:10]
        except Exception:
            pass
        return []
