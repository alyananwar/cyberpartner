#!/usr/bin/env bash
set -e

echo ""
echo "═══════════════════════════════════"
echo "    CyberPartner — Setup"
echo "═══════════════════════════════════"
echo ""

# Python check
if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 not found. Install from python.org"
    exit 1
fi
PY=$(python3 --version 2>&1)
echo "[✓] $PY"

# nmap check
if command -v nmap &>/dev/null; then
    echo "[✓] nmap: $(nmap --version | head -1)"
else
    echo "[!] nmap not found"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "    Install: brew install nmap"
    else
        echo "    Install: sudo apt install nmap"
    fi
    echo "    (scanning commands will be disabled without it)"
fi
echo ""

# Virtual env
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi
echo "[✓] Virtual environment ready"

# Install
echo "[*] Installing dependencies..."
.venv/bin/pip install -e . --quiet
echo "[✓] Dependencies installed"

# .env setup
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ""
    echo "[!] Created .env — add your API keys:"
    echo "    ANTHROPIC_API_KEY=sk-ant-..."
    echo "    (optional) HUNTER_API_KEY=... for email OSINT"
else
    echo "[✓] .env already exists"
fi

echo ""
echo "═══════════════════════════════════"
echo "    Setup complete!"
echo "═══════════════════════════════════"
echo ""
echo "Run:"
echo "  source .venv/bin/activate"
echo "  cyberpartner"
echo ""
echo "Or without activating:"
echo "  .venv/bin/cyberpartner"
echo ""
