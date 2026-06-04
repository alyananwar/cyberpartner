from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, RichLog

from .ai_client import AIClient
from .commands import process
from .recon import Recon
from .reporter import Reporter
from .scanner import Scanner

WELCOME = [
    "[bold green]CyberPartner v1.0[/bold green]  [dim]AI Security Assistant[/dim]",
    "",
    "  [green]scan[/green] [dim]·[/dim] [green]recon[/green] [dim]·[/dim] [green]email[/green] "
    "[dim]·[/dim] [green]ask[/green] [dim]·[/dim] [green]analyze[/green] [dim]·[/dim] [green]report[/green]",
    "  Type [cyan]help[/cyan] for all commands.",
    "",
]


class CyberPartnerApp(App):
    CSS_PATH = Path(__file__).parent / "app.tcss"
    TITLE = "CyberPartner"
    SUB_TITLE = "AI Security"

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True, show=True),
        Binding("ctrl+l", "clear_all", "Clear", show=True),
        Binding("f1", "action_help", "Help", show=True),
    ]

    def __init__(self, ai: AIClient, scanner: Scanner, recon: Recon, reporter: Reporter):
        super().__init__()
        self._ai = ai
        self._scanner = scanner
        self._recon = recon
        self._reporter = reporter
        self._last_result: Optional[str] = None
        self._session: List[dict] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="panes"):
            with Vertical(id="left-pane"):
                yield Label("AI Partner", classes="pane-label")
                yield RichLog(id="chat-log", markup=True, highlight=True, wrap=True)
            with Vertical(id="right-pane"):
                yield Label("Results", classes="pane-label")
                yield RichLog(id="result-log", markup=True, highlight=True, wrap=True)
        with Horizontal(id="input-row"):
            yield Input(placeholder="❯ type a command or question...", id="command-input")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#command-input", Input).focus()
        chat = self.query_one("#chat-log", RichLog)
        for line in WELCOME:
            chat.write(line)

        result = self.query_one("#result-log", RichLog)
        result.write("[dim]No results yet.[/dim]")
        result.write("[dim]Run: scan <ip> | recon <domain> | email <domain>[/dim]")

        if not self._scanner.available:
            chat.write("[yellow]⚠ nmap not found. Scanning disabled.[/yellow]")
            chat.write("[dim]Install: brew install nmap[/dim]")
            chat.write("")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if not raw:
            return

        self.query_one("#command-input", Input).clear()

        chat = self.query_one("#chat-log", RichLog)
        chat.write(f"[bold cyan]❯ {raw}[/bold cyan]")

        if raw.lower() in ("exit", "quit", "q"):
            self.exit()
            return

        if raw.lower() == "clear":
            self.action_clear_all()
            return

        self.run_worker(self._run(raw))

    async def _run(self, raw: str) -> None:
        chat = self.query_one("#chat-log", RichLog)
        result_log = self.query_one("#result-log", RichLog)

        cr = await process(
            raw,
            self._ai,
            self._scanner,
            self._recon,
            self._reporter,
            self._last_result,
            self._session,
        )

        for line in cr.chat:
            chat.write(line)

        if cr.results:
            result_log.clear()
            for line in cr.results:
                result_log.write(line)
            self._last_result = "\n".join(
                line for line in cr.results if isinstance(line, str)
            )

        if cr.session_item:
            self._session.append(cr.session_item)

    def action_clear_all(self) -> None:
        self.query_one("#chat-log", RichLog).clear()
        r = self.query_one("#result-log", RichLog)
        r.clear()
        r.write("[dim]Cleared.[/dim]")

    def action_action_help(self) -> None:
        self.run_worker(self._run("help"))
