# bug-bounty-recon-framework
bug bounty recon framework
```
# ⚡ bug bounty recon framework
 Recon Framework

A fully automated, modular, and aggressive reconnaissance engine designed for **bug bounty**, **attack surface mapping**, and **pentesting workflows**.  
Built for speed, depth, and reliability — even on large enterprise scopes.

---

## 🚀 Features

- **Automated Subdomain Enumeration**  
  Subfinder, Assetfinder, crt.sh, OTX, VirusTotal, URLScan, CommonCrawl, CDX, and more.

- **Live Host Detection**  
  Fast probing using `httpx` + `dnsx`.

- **Massive URL Collection**  
  `gau`, `waybackurls`, `katana`, `waymore`, Archive.org, CommonCrawl, URLScan API.

- **JavaScript Recon**  
  JS file discovery, endpoint extraction, API paths, secrets, and sensitive patterns.

- **API Endpoint Discovery**  
  Automatic extraction from URLs, JS, and archived content.

- **GF Pattern Matching**  
  IDOR, SSRF, LFI, RCE, SQLi, XSS, and custom patterns.

- **Nuclei Vulnerability Scanning**  
  Full template support with auto‑update.

- **Nmap Service Enumeration**  
  Fast + detailed port and service scanning.

- **Metasploit Auxiliary Scanning**  
  Optional deeper service and exploit checks.

- **Full Reporting**  
  Clean output folders, logs, summaries, and OWASP‑style findings.

---

## 📁 Directory Structure

```bash
recon-output/
│
├── subdomains/
├── live/
├── urls/
├── js/
├── api/
├── gf/
├── nuclei/
├── nmap/
├── msf/
└── logs/
```

---

## 🛠️ Installation

### 1. Install Go

```bash
sudo apt update
sudo apt install golang -y
```

### 2. Install required tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

pip install waymore

sudo apt install -y jq nmap curl
```

### 3. Add Go binaries to PATH

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc
source ~/.zshrc
```

---

## 🔑 API Keys (Optional but Recommended)

Add these lines to `~/.zshrc` (replace with your real keys):

```bash
export URLSCAN_API_KEY="your_urlscan_api_key"
export OTX_API_KEY="your_otx_api_key"
export VT_API_KEY="your_virustotal_api_key"
export URLSIO_API_KEY="your_urlsio_api_key"
```

Reload:

```bash
source ~/.zshrc
```

Verify:

```bash
echo $URLSCAN_API_KEY
echo $OTX_API_KEY
echo $VT_API_KEY
echo $URLSIO_API_KEY
```

---
## setup
chmod +x hack.sh
echo 'alias hack="bash ~/hack.sh"' >> ~/.bashrc
source ~/.bashrc
source ~/.zshrc

## 🧪 Usage

### Basic scan

```
hack -d example.com
```

### (Optional) Fast mode

```
hack -d example.com --fast
```

### (Optional) Deep mode

```
hack -d example.com --deep
```

> Adjust flags according to how you implemented them in the script.

---

## 📌 Module Breakdown

### 1. Subdomain Enumeration

- `subfinder`
- `assetfinder`
- `crt.sh`
- OTX (API)
- VirusTotal (API)
- URLScan (API)
- CommonCrawl
- CDX / Archive.org

### 2. DNS Resolution

- `dnsx`

### 3. Live Host Detection

- `httpx`

### 4. URL Harvesting

- `gau`
- `waybackurls`
- `katana`
- `waymore`
- URLScan API
- Archive.org
- CommonCrawl

### 5. JavaScript Recon

- JS file discovery
- Endpoint extraction
- Secret / token patterns

### 6. API Endpoint Mapping

- From URLs
- From JS
- From archives

### 7. GF Pattern Matching

- IDOR
- SSRF
- LFI
- RCE
- SQLi
- XSS
- Custom patterns

### 8. Vulnerability Scanning

- `nuclei`

### 9. Service Enumeration

- `nmap`

### 10. Optional Metasploit Modules

- Auxiliary scanners (if enabled)

---

## 📜 Output Example

```bash
recon-output/example.com/
│
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   └── all.txt
│
├── live/
│   └── live_hosts.txt
│
├── urls/
│   ├── gau.txt
│   ├── waybackurls.txt
│   ├── katana.txt
│   ├── waymore.txt
│   └── all_urls.txt
│
├── js/
│   ├── js_files.txt
│   └── js_endpoints.txt
│
├── api/
│   └── api_endpoints.txt
│
├── gf/
│   ├── idor.txt
│   ├── ssrf.txt
│   ├── lfi.txt
│   ├── rce.txt
│   ├── sqli.txt
│   └── xss.txt
│
├── nuclei/
│   └── findings.txt
│
├── nmap/
│   └── scan.txt
│
├── msf/
│   └── modules.txt
│
└── logs/
    └── run.log
```

---

## ⚠️ Legal Disclaimer

This tool is intended **ONLY** for authorized security testing and educational purposes.  
You must have **explicit, written permission** from the owner of any target you scan.  
The author is **not responsible** for any misuse or damage caused by this tool.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.  
Feel free to:

- Open an issue  
- Submit a pull request  
- Suggest new modules or integrations  

---

## ⭐ Author

**Tanvir Ahmed**  
Security Researcher • Bug Bounty Hunter • Automation Engineer
```
