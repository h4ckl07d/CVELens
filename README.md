# CVELens 🔍
> Vulnerability Intelligence Engine — powered by Groq × GPT-OSS-120B

CVELens is a CLI-based vulnerability intelligence tool that takes a CVE ID and produces a structured, security briefing directly in your terminal.  It pulls live data from NIST NVD and CISA KEV, then uses Groq's fast inference to generate a full threat report — attack mechanics, CVSS breakdown, affected surface, impact analysis, and remediation guidance

## Requirements
- Python 3.8+
- A free Groq API key → https://console.groq.com

## Installation
### Linux/ Mac

```bash
# 1. Clone the repo
git clone https://github.com/h4ckl07d/CVELens.git
cd CVELens

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up your API key
cp .env.example .env
nano .env          # paste your GROQ_API_KEY

# 4. Run
python3 cvelens.py CVE-2021-44228
```
### Windows
```bash
# 1. Clone the repo
git clone https://github.com/h4ckl07d/CVELens.git
cd CVELens

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up your API key
copy .env.example .env
notepad .env       # paste your GROQ_API_KEY
```

## Optional — install as a global command

```bash
pip install .
cvelens CVE-2021-44228
```

## Usage

```bash
cvelens CVE-2021-44228               # standard report
cvelens CVE-2021-44228 --short       # executive brief
cvelens CVE-2021-44228 -v            # verbose technical detail
cvelens CVE-2021-44228 --code        # include exploit pseudocode
cvelens CVE-2021-44228 --deep        # full intelligence dump
```

## Flags

| Flag | Description |
|------|-------------|
| `-v` | Deep technical detail + attack chains |
| `--short` | Executive briefing, max 250 words |
| `--code` | Annotated exploit pseudocode block |
| `--deep` | Full dump: TTPs, threat actors, timeline |

## Getting a Groq API Key
1. Go to https://console.groq.com
2. Sign up / log in
3. Navigate to API Keys → Create Key
4. Copy it into your `.env` file