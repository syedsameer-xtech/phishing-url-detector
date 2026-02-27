# 🛡️ Phishing URL Detector

<div align="center">

### A Python-Based Heuristic Tool for Detecting Suspicious URLs

🔍 Keyword Detection • 🌐 IP Checks • 🧬 Subdomain Analysis • 🎯 Typosquatting Detection  

</div>

---

> ⚠️ **Disclaimer**  
> This tool uses rule-based heuristics for educational purposes.  
> It is **NOT** a replacement for professional security solutions, browser protections, or threat intelligence services.  
> Always verify URLs using multiple trusted sources.

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Test URLs](#-sample-test-urls)
- [How It Works](#-how-it-works)
- [Customization](#-customization)
- [Contributing](#-contributing)
- [License](#-license)
- [Stay Safe Online](#-stay-safe-online)

---

## 🎯 Overview

The **Phishing URL Detector** is a lightweight Python tool that evaluates URLs using heuristic-based analysis.

It is designed for:

- 🎓 Cybersecurity students  
- 🧠 Beginners learning about phishing attacks  
- 🏁 CTF practice  
- 🔍 Quick manual URL evaluation  

The detector assigns a **risk score** based on suspicious characteristics commonly seen in phishing campaigns.

---

## 🚀 Features

- 🔍 **Keyword Detection**  
  Scans for phishing-related terms like `login`, `verify`, `account`, `secure`, etc.

- 🌐 **IP Address Check**  
  Flags URLs that use raw IP addresses instead of domain names.

- 🧬 **Subdomain Analysis**  
  Detects excessive subdomains (common in spoofing attacks).

- 🎯 **Typosquatting Detection**  
  Identifies brand impersonation (`paypa1`, `faceb00k`, `g00gle`).

- 🚫 **Malicious TLD Filter**  
  Warns about high-risk extensions like `.tk`, `.ga`, `.ru`, `.xyz`.

- 🔗 **URL Shortener Alert**  
  Flags shortened links that may hide real destinations.

- 🕵️ **Anti-Evasion Checks**  
  Detects tricks like `@` symbols used to disguise real domains.

- 💬 **Explainable Results**  
  Clearly shows *why* a URL was flagged.

---

## 📂 Project Structure

```
phishing-url-detector/
├── phishing_detector.py      # Main detection script
├── requirements.txt          # Dependencies
├── sample_test_urls.txt      # Example URLs
└── README.md                 # Documentation
```

---

## 🧑‍💻 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Run Interactive Mode

```bash
python phishing_detector.py
```

Example:

```
🛡️ Phishing URL Detector
Tip: Enter URLs like 'https://example.com/login'
Type 'quit' to exit

Enter URL to check:
https://secure-paypa1-login.tk/verify/account

Result: 🚨 Likely phishing
Reasons:
- Suspicious keywords in path/query
- Suspicious TLD: .tk
- Possible brand impersonation
```

---

### Run Batch Testing

```bash
python -c "
from phishing_detector import detect_phishing
with open('sample_test_urls.txt') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            url = line.split('|')[0].strip()
            print(f'{url} -> {detect_phishing(url)}')
"
```

---

## 🧪 Sample Test URLs

The `sample_test_urls.txt` file includes:

- ✅ Safe URLs  
- ⚠️ Suspicious URLs  
- 🚨 High-risk phishing attempts  
- ❌ Malformed inputs  
- 💡 Edge cases  

Quick test example:

```python
from phishing_detector import detect_phishing

test_urls = [
    "https://www.google.com",
    "https://paypa1.com/verify",
    "http://192.168.1.1/login",
    "https://sub1.sub2.evil.tk/account"
]

for url in test_urls:
    print(f"{url}\n→ {detect_phishing(url)}\n")
```

---

## ⚙️ How It Works

The detector assigns a weighted score based on heuristics.

| Check | Score | Description |
|--------|-------|------------|
| IP address in URL | +2 | Phishers often avoid domain blacklists |
| Suspicious keywords | +2 | `login`, `verify`, etc. |
| Malicious TLD | +2 | High-abuse domain extensions |
| Typosquatting | +2 | Brand impersonation |
| `@` symbol in URL | +2 | Hides real destination |
| URL shortener | +1 | Masks actual link |
| Excessive subdomains | +1 | Spoofing tactic |

### Classification

- 🚨 **Likely phishing** → Score ≥ 5  
- ⚠️ **Suspicious** → Score 3–4  
- ✅ **Likely safe** → Score ≤ 2  

---

## 🛠️ Customization

### Add More Suspicious Keywords

Edit `phishing_detector.py`:

```python
suspicious_keywords = [
    'login', 'verify', 'update', 'secure', 'account',
    'webscr', 'signin', 'bank', 'confirm',
    'validate', 'password', 'unlock'
]
```

### Modify TLD List

```python
bad_tlds = ['.tk', '.ga', '.ml', '.cf', '.gq', '.ru', '.xyz', '.top', '.click']
```

### Adjust Risk Threshold

```python
if score >= 6:
    return "🚨 Likely phishing"
elif score >= 4:
    return "⚠️ Suspicious"
```

---

## 🤝 Contributing

Contributions are welcome!

Ideas:

- WHOIS/domain age checking  
- Google Safe Browsing API integration  
- JSON/CSV output  
- Web interface or GUI  
- Machine learning classifier  

### Steps

```bash
git checkout -b feature/AmazingFeature
git commit -m "✨ Add AmazingFeature."
git push origin feature/AmazingFeature
```

Then open a Pull Request 🙌

---

## 📜 License

MIT License — Free for educational and personal use.

---

## 🙏 Acknowledgements

- `tldextract` — Domain parsing  
- PhishTank — Community phishing data  
- Google Safe Browsing — Industry reference  
- Cybersecurity educators & CTF creators  

---

## 🔐 Stay Safe Online

✅ Check domains carefully  
✅ Hover over links before clicking  
✅ Use a password manager  
✅ Enable 2FA  
❌ Never enter credentials on suspicious websites  

---

<div align="center">

Built with ❤️ for a safer internet  

Made with ❤️ by ChatGPT, Qwen 
Prompted by Syed Sameer  

⭐ Star this repository if you found it useful!  
🔝 Back to Top  

</div>
