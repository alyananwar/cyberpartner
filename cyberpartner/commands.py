from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ai_client import AIClient
from .scanner import Scanner
from .recon import Recon
from .reporter import Reporter


@dataclass
class CommandResult:
    chat: List[str] = field(default_factory=list)
    results: List[str] = field(default_factory=list)
    session_item: Optional[Dict[str, Any]] = None


async def process(
    raw: str,
    ai: AIClient,
    scanner: Scanner,
    recon: Recon,
    reporter: Reporter,
    last_result: Optional[str],
    session_data: List[dict],
) -> CommandResult:
    parts = raw.strip().split(maxsplit=2)
    cmd = parts[0].lower() if parts else ""

    if cmd == "help":
        return _help()
    if cmd == "scan":
        return await _scan(parts, scanner, ai)
    if cmd == "email":
        return await _email(parts, recon)
    if cmd == "recon":
        return await _recon(parts, recon)
    if cmd in ("ask", "chat"):
        question = raw[len(cmd):].strip()
        return await _ask(question, ai, session_data)
    if cmd == "analyze":
        return await _analyze(last_result, ai)
    if cmd == "report":
        name = parts[1] if len(parts) > 1 else None
        return await _report(name, session_data, reporter)
    if cmd == "model":
        if len(parts) > 1:
            ai.set_model(parts[1])
            return CommandResult(chat=[f"[green]Model set to {parts[1]}[/green]"])
        return CommandResult(chat=[f"[dim]Current model: {ai.model}[/dim]"])
    if cmd == "reset":
        ai.reset()
        return CommandResult(chat=["[dim]AI conversation history cleared.[/dim]"])

    # fallback: send anything to AI
    return await _ask(raw, ai, session_data)


async def _scan(parts: List[str], scanner: Scanner, ai: AIClient) -> CommandResult:
    res = CommandResult()

    if len(parts) < 2:
        res.chat = ["[red]Usage: scan <target> | scan quick/full/vuln <target>[/red]"]
        return res

    # parse subcommands
    subcommands = {"quick", "fast", "full", "vuln", "vulnerability", "ping"}
    if parts[1].lower() in subcommands and len(parts) >= 3:
        scan_type = "quick" if parts[1].lower() in ("quick", "fast") else parts[1].lower()
        if scan_type == "vulnerability":
            scan_type = "vuln"
        target = parts[2]
    else:
        target = parts[1]
        scan_type = "default"

    res.chat.append(f"[yellow]Scanning {target} ({scan_type})...[/yellow]")

    sr = await scanner.scan(target, scan_type)

    if sr.error:
        res.chat.append(f"[red]{sr.error}[/red]")
        res.results = sr.formatted_lines
        return res

    res.results = sr.formatted_lines

    if sr.open_ports:
        ports_str = ", ".join(str(p) for p in sr.open_ports[:6])
        res.chat.append(f"[green]{len(sr.open_ports)} open port(s): {ports_str}[/green]")
        res.chat.append("[dim]Type [cyan]analyze[/cyan] for AI analysis[/dim]")
    else:
        res.chat.append("[dim]No open ports found[/dim]")

    res.session_item = {
        "type": "scan",
        "target": target,
        "data": sr.raw,
        "ports_summary": ", ".join(str(p) for p in sr.open_ports),
    }
    return res


async def _email(parts: List[str], recon: Recon) -> CommandResult:
    res = CommandResult()

    if len(parts) < 2:
        res.chat = ["[red]Usage: email <domain> [Firstname Lastname][/red]"]
        return res

    domain = parts[1]
    name = parts[2] if len(parts) > 2 else None

    res.chat.append(f"[yellow]Looking up email pattern for {domain}...[/yellow]")

    er = await recon.find_email_pattern(domain, name)
    res.results = er.formatted_lines

    if er.pattern:
        res.chat.append(f"[green]Pattern: {er.pattern}@{domain}[/green]")
    if er.emails:
        res.chat.append(f"[green]{len(er.emails)} candidate(s) generated[/green]")

    res.session_item = {"type": "email", "domain": domain, "data": er.to_dict()}
    return res


async def _recon(parts: List[str], recon: Recon) -> CommandResult:
    res = CommandResult()

    if len(parts) < 2:
        res.chat = ["[red]Usage: recon <domain>[/red]"]
        return res

    domain = parts[1]
    res.chat.append(f"[yellow]Running OSINT recon on {domain}...[/yellow]")

    rr = await recon.run_recon(domain)
    res.results = rr.formatted_lines

    if rr.subdomains:
        res.chat.append(f"[green]{len(rr.subdomains)} subdomain(s) found[/green]")
    if rr.ip:
        res.chat.append(f"[green]IP: {rr.ip}[/green]")
    res.chat.append("[dim]Type [cyan]analyze[/cyan] for AI analysis[/dim]")

    res.session_item = {"type": "recon", "domain": domain, "data": rr.to_dict()}
    return res


async def _ask(question: str, ai: AIClient, session_data: List[dict]) -> CommandResult:
    res = CommandResult()

    if not question.strip():
        res.chat = ["[red]Usage: ask <question>[/red]"]
        return res

    res.chat.append("[dim]Thinking...[/dim]")
    ctx = _build_context(session_data)
    reply = await ai.ask(question, ctx)

    res.chat.append("")
    res.chat.append("[bold green]AI ▶[/bold green]")
    for line in reply.split("\n"):
        res.chat.append(f"  [green]{line}[/green]" if line.strip() else "")
    res.chat.append("")
    return res


async def _analyze(last_result: Optional[str], ai: AIClient) -> CommandResult:
    res = CommandResult()

    if not last_result:
        res.chat = ["[red]No previous result. Run scan or recon first.[/red]"]
        return res

    res.chat.append("[dim]Analyzing with AI...[/dim]")
    prompt = (
        "Analyze the following security scan/recon output. Identify:\n"
        "1. Key findings\n2. Attack vectors or misconfigs\n3. Recommended next steps\n\n"
        f"DATA:\n{last_result[:3000]}"
    )
    reply = await ai.ask(prompt)

    res.chat.append("")
    res.chat.append("[bold green]AI Analysis ▶[/bold green]")
    for line in reply.split("\n"):
        res.chat.append(f"  [green]{line}[/green]" if line.strip() else "")
    res.chat.append("")

    res.session_item = {"type": "ai_analysis", "content": reply}
    return res


async def _report(
    name: Optional[str], session_data: List[dict], reporter: Reporter
) -> CommandResult:
    res = CommandResult()

    if not session_data:
        res.chat = ["[red]No data to report. Run some commands first.[/red]"]
        return res

    filepath = await reporter.generate(session_data, name)
    res.chat = [f"[green]Report saved → {filepath}[/green]"]
    return res


def _build_context(session_data: List[dict]) -> str:
    if not session_data:
        return ""
    items = []
    for item in session_data[-4:]:
        t = item["type"]
        tgt = item.get("target") or item.get("domain", "")
        items.append(f"{t} on {tgt}")
    return "Previous session actions: " + ", ".join(items)


def _help() -> CommandResult:
    res = CommandResult()
    res.chat = [
        "",
        "[bold green]╔══ CyberPartner Commands ══════════════╗[/bold green]",
        "",
        "[bold cyan]SCANNING[/bold cyan]",
        "  [cyan]scan <target>[/cyan]           nmap default scan",
        "  [cyan]scan quick <target>[/cyan]     fast top-1000 ports",
        "  [cyan]scan full <target>[/cyan]      all 65535 ports",
        "  [cyan]scan vuln <target>[/cyan]      run nmap vuln scripts",
        "",
        "[bold cyan]OSINT / EMAIL[/bold cyan]",
        "  [cyan]email <domain>[/cyan]          detect email pattern",
        "  [cyan]email <domain> <name>[/cyan]   generate specific email",
        "  [cyan]recon <domain>[/cyan]          DNS + subdomains + certs",
        "",
        "[bold cyan]AI ASSISTANT[/bold cyan]",
        "  [cyan]ask <question>[/cyan]          free-form AI question",
        "  [cyan]analyze[/cyan]                 AI analysis of last result",
        "  [cyan]model <model-id>[/cyan]        switch Claude model",
        "  [cyan]reset[/cyan]                   clear AI chat history",
        "",
        "[bold cyan]UTILITY[/bold cyan]",
        "  [cyan]report [name][/cyan]           save Markdown report",
        "  [cyan]clear[/cyan]                   clear both panes",
        "  [cyan]exit[/cyan]                    quit",
        "",
        "[dim]Any unrecognized input → sent to AI[/dim]",
        "",
    ]
    return res
