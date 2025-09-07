# 🛠 Recon Automation Tool
***tested on ubuntu and kali***

A modular, CLI-based recon automation script written in Python to streamline reconnaissance tasks during bug bounty hunting or penetration testing. It integrates multiple popular tools for subdomain enumeration, service discovery, web probing, fuzzing, and more.

## 📦 Features

Subdomain Enumeration:

- Subfinder

- Findomain

- Assetfinder

Live Subdomain Detection:

- httprobe

Visual Mapping:

- Aquatone

Passive Recon:

- waybackurls

Port Scanning:

- RustScan

- Smap

Directory Bruteforce:

- ffuf

Smart result merging and output management

## 📁 Output Structure

Results are saved in a folder named after the target domain:

```markdown
└── example.com/
    ├── assetfinder.txt
    ├── subfinder.txt
    ├── findomain.txt
    ├── all_subdomains.txt
    ├── live_subdomains.txt
    ├── aquatone_report/
    ├── rustscan_results/
    ├── smap_results/
    ├── waybackurls_results/
    └── ffuf_results/
```
## 🚀 Usage
```python3 recon.py <domain> [options]```

## 🔧 Help Description
```
<domain>	Target domain (required)
-s, --subfinder Run Subfinder
-f, --findomain	Run Findomain
-a, --assetfinder Run Assetfinder
-x, --httprobe	Probe live subdomains
-q, --aquatone	Run Aquatone
-r, --rustscan	Run RustScan
-S, --smap	Run Smap (full port scan)
-u, --ffuf	Run ffuf for directory fuzzing
-w, --wordlist <file>	Wordlist to use with ffuf (required if using -u or -A)
-b, --waybackurls	Run waybackurls
-A, --all	Run all available tools
--passive	Run only passive tools
-h, --help	Show help message and exit
```
## 🌐 Examples

### Run all recon modules:

`python3 recon.py example.com -A -w /path/to/wordlist.txt`


### Passive recon only:

`python3 recon.py example.com --passive`


### Run selected tools:

`python3 recon.py example.com -s -f -x -r`


### Run ffuf with a wordlist:

`python3 recon.py example.com -u -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
