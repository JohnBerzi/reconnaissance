#!/bin/bash

set -e

echo "[*] Updating system..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing base packages..."
sudo apt install -y git curl wget unzip build-essential jq chromium nmap dnsutils cargo lsb-release

echo "[*] Installing Python3 and pip..."
sudo apt install -y python3 python3-pip

# For Future use: requirements.txt
# echo "[*] Installing Python dependencies..."
# pip3 install -r requirements.txt

# Optional: Install sudo if missing (for minimal installations)
if ! command -v sudo &>/dev/null; then
  echo "[*] Installing sudo..."
  su -c 'apt install -y sudo'
fi

install_go() {
  if ! command -v go &> /dev/null; then
    echo "[*] Installing Go..."
    wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    source ~/.bashrc
    rm go1.22.3.linux-amd64.tar.gz
  else
    echo "[✓] Go is already installed."
  fi
}

install_go

echo "[*] Installing Go-based tools..."

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httprobe
go install github.com/tomnomnom/httprobe@latest

# ffuf
go install github.com/ffuf/ffuf@latest

# Amass
go install github.com/owasp-amass/amass/v4/...@master

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest

echo "[*] Installing Smap..."
go install -v github.com/s0md3v/smap/cmd/smap@latest


echo "[*] Installing Findomain..."
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

echo "[*] Installing Aquatone..."
wget https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64.zip
unzip aquatone_linux_amd64.zip
chmod +x aquatone
sudo mv aquatone /usr/local/bin/
rm aquatone_linux_amd64.zip

echo "[*] Installing RustScan..."
cargo install rustscan

echo
echo "[✓] All tools installed successfully!"
echo "Make sure the following path is in your ~/.bashrc:"
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
