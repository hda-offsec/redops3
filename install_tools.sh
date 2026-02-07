#!/bin/bash
# Setup script for RedOps3 External Tools
# Optimized for Kali Linux

set -e

echo "--- RedOps3 Tool Installer ---"

# Update apt
echo "[+] Updating apt repositories..."
sudo apt update || true

# Install Python dependencies (just in case)
echo "[+] Installing system dependencies..."
sudo apt install -y python3-pip redis-server nmap whatweb ffuf golang jq

# Install ProjectDiscovery tools via pdtm (official manager)
echo "[+] Installing pdtm (ProjectDiscovery Tool Manager)..."
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest || true

# Add Go bin to path for current session
export PATH=$PATH:$HOME/go/bin

if command -v pdtm &> /dev/null; then
    echo "[+] Using pdtm to install Nuclei, Katana, Subfinder..."
    pdtm -install nuclei,katana,subfinder
else
    echo "[!] pdtm failed, falling back to direct go install..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest || true
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
fi

# Ensure they are in ~/go/bin
ls -l $HOME/go/bin/

echo "--- Installation Complete ---"
echo "Please run: source ~/.zshrc"
