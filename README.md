<p align="center">
  <img src="https://raw.githubusercontent.com/atenreiro/opensquat/master/screenshots/openSquat_logo.png" alt="openSquat Logo" width="400"/>
</p>

<h1 align="center">openSquat</h1>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/python-3.6+-blue.svg" alt="Python 3.6+"></a>
  <a href="https://github.com/atenreiro/opensquat/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
  <a href="https://github.com/atenreiro/opensquat/issues"><img src="https://img.shields.io/github/issues/atenreiro/opensquat" alt="GitHub issues"></a>
  <a href="https://github.com/atenreiro/opensquat/stargazers"><img src="https://img.shields.io/github/stars/atenreiro/opensquat" alt="GitHub stars"></a>
</p>

---

## 📑 Table of Contents

- [What is openSquat?](#-what-is-opensquat)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Requirements](#-requirements)
- [Usage](#-usage)
- [Configuration](#%EF%B8%8F-configuration)
- [Automation](#-automation)
- [Integrations](#-integrations)
- [CLI Reference](#-cli-reference)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🎯 What is openSquat?

openSquat is an **Open Source Intelligence (OSINT)** security tool that identifies cyber squatting threats targeting your brand or domains:

| Threat Type | Description |
|-------------|-------------|
| 🎣 **Phishing** | Fraudulent domains mimicking your brand |
| 🔤 **Typosquatting** | Domains with common typos (e.g., `gooogle.com`) |
| 🌐 **IDN Homograph** | Look-alike characters from other alphabets |
| 👥 **Doppelgänger** | Domains containing your brand name |
| 🔀 **Bitsquatting** | Single-bit errors in domain names |

## ✨ Key Features

- 📅 **Daily NRD feeds** — Automatic newly registered domain updates
- 🔍 **Similarity detection** — Levenshtein & Jaro-Winkler algorithms
- 🛡️ **VirusTotal integration** — Check domain reputation
- 🌐 **Quad9 DNS validation** — Identify malicious domains
- 📜 **Certificate Transparency** — Monitor SSL/TLS certificates
- 📊 **Multiple output formats** — TXT, JSON, CSV

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/atenreiro/opensquat
cd opensquat

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run with your keywords
python opensquat.py -k keywords.txt
```

---

## 📦 Requirements

- **Python 3.6+**
- Dependencies: `colorama`, `dnspython`, `requests`, `beautifulsoup4`

---

## 📖 Usage

### Basic Commands

```bash
# Default run
python opensquat.py

# Show all options
python opensquat.py -h

# Use custom keywords file
python opensquat.py -k my_keywords.txt
```

### Validation Options

```bash
# DNS validation via Quad9
python opensquat.py --dns

# Check Certificate Transparency logs
python opensquat.py --ct

# Scan for open ports (80/443)
python opensquat.py --portcheck

# Cross-reference phishing databases
python opensquat.py --phishing results.txt
```

### Output Formats

```bash
# Save as JSON
python opensquat.py -o results.json -t json

# Save as CSV
python opensquat.py -o results.csv -t csv
```

### Confidence Levels

| Level | Flag | Description |
|-------|------|-------------|
| 0 | `-c 0` | Very high (fewer results, high accuracy) |
| 1 | `-c 1` | High (default) |
| 2 | `-c 2` | Medium |
| 3 | `-c 3` | Low |
| 4 | `-c 4` | Very low (more results, more false positives) |

---

## ⚙️ Configuration

### Keywords File (`keywords.txt`)

```text
# Lines starting with # are comments
mycompany
mybrand
myproduct
```

### VirusTotal API Key (`vt_key.txt`)

To use `--vt` or `--subdomains`, add your API key:
```text
# Get your free API key at https://www.virustotal.com
your_api_key_here
```

---

## 🤖 Automation

Run daily via crontab:

```bash
# Every day at 8 AM (feeds update ~7:30 AM UTC)
0 8 * * * /path/to/opensquat/opensquat.py -k keywords.txt -o results.json -t json
```

---

## 🔗 Integrations

| Platform | Link |
|----------|------|
| 🤖 Telegram Bot | [@opensquat_bot](https://telegram.me/opensquat_bot) |
| 🔌 REST API | [RapidAPI](https://rapidapi.com/atenreiro/api/opensquat1) |

---

## 📋 CLI Reference

| Argument | Default | Description |
|----------|---------|-------------|
| `-k, --keywords` | `keywords.txt` | Keywords file to search |
| `-o, --output` | `results.txt` | Output filename |
| `-t, --type` | `txt` | Output format: `txt`, `json`, `csv` |
| `-c, --confidence` | `1` | Confidence level (0-4) |
| `-d, --domains` | — | Use local domain file instead of downloading |
| `-m, --method` | `Levenshtein` | Algorithm: `Levenshtein` or `JaroWinkler` |
| `--dns` | — | Enable Quad9 DNS validation |
| `--ct` | — | Search Certificate Transparency logs |
| `--phishing` | — | Cross-reference phishing database |
| `--subdomains` | — | Fetch subdomains via VirusTotal |
| `--portcheck` | — | Check for open ports 80/443 |
| `--vt` | — | Validate against VirusTotal |

---

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

- 🐛 **Report bugs** via [GitHub Issues](https://github.com/atenreiro/opensquat/issues)
- 💡 **Request features** by opening an issue
- 🔧 **Submit PRs** for bug fixes or enhancements

---

## 👤 Author

**Andre Tenreiro** — [LinkedIn](https://www.linkedin.com/in/andretenreiro/) · [PGP Key](https://mail-api.proton.me/pks/lookup?op=get&search=andre@opensquat.com)

---

## 📜 License

This project is licensed under the [GNU GPL v3](LICENSE).
