# CyberPartner

**A terminal security assistant. Run nmap and domain recon, then ask Claude what the results mean.**

<p align="center">
  <img src="docs/demo.gif" alt="CyberPartner terminal UI running a quick nmap scan of localhost" width="800">
</p>

I built this while studying for security roles. Reading raw nmap output and then looking up every service by hand got old, so I put the scan, the recon, and an AI chat in one split-screen terminal app. The left pane is the chat, the right pane is the raw results.

## Install

You need Python 3.9+ and an [Anthropic API key](https://console.anthropic.com). nmap is optional, but scans need it (`brew install nmap` on Mac, `sudo apt install nmap` on Linux).

```bash
git clone https://github.com/alyananwar/cyberpartner && cd cyberpartner && ./setup.sh
```

`setup.sh` makes a virtual environment, installs the app, and creates `.env`. Put your key in `.env`, then run:

```bash
.venv/bin/cyberpartner
```

## Commands

| Command                             | What it does                                                                                  |
| ----------------------------------- | --------------------------------------------------------------------------------------------- |
| `scan <target>`                     | nmap service scan of the top 1000 ports                                                       |
| `scan quick / full / vuln <target>` | Faster scan, all 65535 ports, or nmap's vuln scripts                                          |
| `recon <domain>`                    | IP, MX records (and whether mail runs on Google or Microsoft), common subdomains that resolve |
| `email <domain> [First Last]`       | Guesses a company's email format. Uses Hunter.io if you add `HUNTER_API_KEY`                  |
| `analyze`                           | Sends the last result to Claude and asks what's worth looking at next                         |
| `ask <question>`                    | Free-form question. Anything that isn't a command goes to the AI too                          |
| `model <model-id>`                  | Switch Claude models (default is Haiku, the cheap one)                                        |
| `report [name]`                     | Saves the session as a Markdown report on your Desktop                                        |
| `reset` / `clear` / `exit`          | Clear the AI chat, clear both panes, quit                                                     |

## How it works

- **UI:** [Textual](https://textual.textualize.io/) for the split-pane terminal app.
- **Scanning:** runs `nmap` as a subprocess and parses the open ports and services.
- **Recon:** standard DNS lookups plus a list of common subdomain names. No API needed.
- **AI:** the Anthropic Python SDK. Scan and recon output is sent to Claude only when you run `analyze` or `ask`, so nothing leaves your machine unless you ask for it.

## Use it responsibly

Only scan systems you own or have written permission to test. The app warns you when a target isn't on a private network. `scanme.nmap.org` and your own machine (`127.0.0.1`) are safe places to try it.

## License

No license file yet.
