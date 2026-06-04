# LinkedIn Post — CyberPartner

---

Built a local AI-powered security assistant this weekend. Terminal UI, runs fully offline, no data leaves your machine.

**What it does:**

- `scan <target>` — wraps nmap with AI-interpreted output (open ports, services, flags for misconfigs)
- `recon <domain>` — DNS, MX records, subdomain enumeration, cert transparency lookup via crt.sh
- `email <domain> <name>` — detects company email format via Hunter.io and generates candidates for cold outreach
- `analyze` — pipes last result directly into Claude for security analysis and next-step recommendations
- `report` — exports a clean Markdown session report

**Why I built it:**

I'm prepping for cybersecurity and cloud security roles, and I wanted a tool that feels less like a textbook lab and more like a real workflow. Taking nmap output and immediately asking an AI "what's worth poking at here?" is way more useful than memorizing syntax.

The email pattern feature is for me specifically — I'm starting to cold outreach to security engineers and SOC analysts at companies I want to work at. Finding the email format from a domain + LinkedIn name gets you past the recruiter gatekeeping.

**Stack:**

- Python + Textual (the TUI framework behind tools like Claude Code)
- Anthropic Claude API (claude-haiku for speed + cost)
- nmap via subprocess
- Hunter.io free API + SMTP fallback for email OSINT
- crt.sh for cert transparency

Runs on Mac/Linux. Drop your Anthropic API key in `.env` and you're live in 2 minutes.

Happy to share the code — DM me or comment below.

#cybersecurity #python #ai #pentesting #osint #soc #cloudsecurity #buildinpublic

---

**Screenshot tip:** Run `recon github.com` or `email stripe.com Patrick Collison` for a good screenshot moment.
