# OSINT Intelligence Platform

A web-based Open Source Intelligence (OSINT) platform that analyzes target websites/domains using **10 free OSINT tool APIs** and presents results in a comparison table with Excel export.

## OSINT Tools Used

| # | Tool | Purpose | Free Tier |
|---|------|---------|-----------|
| 1 | **VirusTotal** | Malware/URL scanning & reputation | 500 requests/day |
| 2 | **Shodan** | Port scanning & device intelligence | 100 results/month |
| 3 | **SecurityTrails** | DNS records & domain history | 50 requests/month |
| 4 | **IPinfo** | IP geolocation & ASN data | 50K requests/month |
| 5 | **AbuseIPDB** | IP abuse reports & threat scoring | 1000 checks/day |
| 6 | **URLScan.io** | Website scanning & technology detection | 100 scans/day |
| 7 | **WhoisXML API** | WHOIS domain registration data | 500 queries/month |
| 8 | **AlienVault OTX** | Threat intelligence & pulse data | Unlimited |
| 9 | **GreyNoise** | Internet noise & scanner detection | 100 requests/day |
| 10 | **Hunter.io** | Email discovery & organization info | 25 requests/month |

## Features

- Analyze any domain/website with 10 OSINT APIs simultaneously
- Individual tool result cards with status indicators
- Side-by-side comparison table of all tool results
- **Export to Excel (.xlsx)** with multiple sheets:
  - Comparison table
  - Individual tool result sheets
  - Summary report
- Dark-themed responsive UI
- Real-time progress tracking

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/osint-platform.git
cd osint-platform
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure API keys

Copy the example environment file and add your free API keys:

```bash
cp .env.example .env
```

Sign up for free API keys at:
- VirusTotal: https://www.virustotal.com/gui/join-us
- Shodan: https://account.shodan.io/register
- SecurityTrails: https://securitytrails.com/app/signup
- IPinfo: https://ipinfo.io/signup
- AbuseIPDB: https://www.abuseipdb.com/register
- URLScan.io: https://urlscan.io/user/signup
- WhoisXML API: https://whoisxmlapi.com/
- AlienVault OTX: https://otx.alienvault.com/
- GreyNoise: https://www.greynoise.io/
- Hunter.io: https://hunter.io/users/sign_up

### 4. Run the application

```bash
npm start
```

Open http://localhost:3000 in your browser.

## Usage

1. Enter a target domain (e.g., `example.com`) in the search bar
2. Click **Analyze Target** to query all 10 OSINT tools
3. View individual tool results in cards and the comparison table
4. Click **Export to Excel** to download the results as an `.xlsx` file

## Deployment

The platform can be deployed to Vercel:

```bash
vercel --prod
```

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **APIs**: 10 OSINT tool REST APIs
- **Excel Export**: SheetJS (xlsx library)

## Course Info

**OSINT Course - Task 1**  
Instructor: Hilmand Khan  
Student: Khubab Ahmed

---

*All tools use free API tiers. No paid subscriptions required.*
