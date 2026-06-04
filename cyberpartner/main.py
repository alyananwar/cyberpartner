from __future__ import annotations

import sys
from pathlib import Path

import click
from dotenv import load_dotenv

# Load .env from project root or home
for _p in [Path(".env"), Path(__file__).parent.parent / ".env", Path.home() / ".cyberpartner.env"]:
    if _p.exists():
        load_dotenv(_p)
        break


@click.command()
@click.option(
    "--api-key", envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key (or set ANTHROPIC_API_KEY in .env)"
)
@click.option(
    "--hunter-key", envvar="HUNTER_API_KEY", default=None,
    help="Hunter.io API key for email pattern detection (optional)"
)
@click.option(
    "--model", default="claude-haiku-4-5-20251001", show_default=True,
    help="Claude model to use (haiku=cheap, sonnet=smarter)"
)
def main(api_key: str, hunter_key: str, model: str) -> None:
    """CyberPartner — AI-Powered Local Security Assistant"""

    if not api_key:
        click.echo("[!] ANTHROPIC_API_KEY not set.")
        click.echo("    Set it in .env or pass --api-key")
        click.echo("    Get key: https://console.anthropic.com")
        sys.exit(1)

    from .ai_client import AIClient
    from .app import CyberPartnerApp
    from .recon import Recon
    from .reporter import Reporter
    from .scanner import Scanner

    ai = AIClient(api_key=api_key, model=model)
    scanner = Scanner()
    recon = Recon(hunter_api_key=hunter_key)
    reporter = Reporter()

    app = CyberPartnerApp(ai, scanner, recon, reporter)
    app.run()


if __name__ == "__main__":
    main()
