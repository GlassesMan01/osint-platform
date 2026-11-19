# OSINT Intelligence Platform

A web-based Open Source Intelligence (OSINT) platform that analyzes target websites/domains using **13 free OSINT tool APIs** and presents results in a comparison table with Excel export.

## Live Demo

**https://osint-platform-ashen.vercel.app**

## GitHub Repository

**https://github.com/GlassesMan01/osint-platform**

## OSINT Tools Used

| # | Tool | Purpose | Free Tier |
|---|------|---------|-----------|
| 1 | **VirusTotal** | Malware/URL scanning & reputation | 500 requests/day |
| 2 | **Shodan** | Port scanning & device intelligence | 100 results/month |
| 3 | **IPinfo** | IP geolocation & ASN data | 50K requests/month |
| 4 | **AbuseIPDB** | IP abuse reports & threat scoring | 1000 checks/day |
| 5 | **URLScan.io** | Website scanning & technology detection | 100 scans/day |
| 6 | **AlienVault OTX** | Threat intelligence & pulse data | Unlimited |
| 7 | **GreyNoise** | Internet noise & scanner detection | 100 requests/day |
| 8 | **Censys** | Host & certificate intelligence | 250 queries/month |
| 9 | **ViewDNS** | DNS records & IP history | 250 queries/day |
| 10 | **DNSdumpster** | DNS reconnaissance & mapping | Free |
| 11 | **Cloudflare Radar** | Domain popularity & categorization | Free (public API) |
| 12 | **LeakIX** | Exposed services & leak detection | Free |
| 13 | **Pulsedive** | Threat intelligence & indicators | Free |

## Features

- Analyze any domain/website with 13 OSINT APIs simultaneously
- Individual tool result cards with status indicators (SUCCESS/ERROR)
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
git clone https://github.com/GlassesMan01/osint-platform.git
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
- IPinfo: https://ipinfo.io/signup
- AbuseIPDB: https://www.abuseipdb.com/register
- URLScan.io: https://urlscan.io/user/signup
- AlienVault OTX: https://otx.alienvault.com/
- GreyNoise: https://www.greynoise.io/
- Censys: https://search.censys.io/register
- ViewDNS: https://viewdns.info/api/
- DNSdumpster: https://dnsdumpster.com/
- LeakIX: https://leakix.net/
- Pulsedive: https://pulsedive.com/

### 4. Run the application

```bash
npm start
```

Open http://localhost:3000 in your browser.

## Usage

1. Enter a target domain (e.g., `example.com`) in the search bar
2. Click **Analyze Target** to query all 13 OSINT tools
3. View individual tool results in cards and the comparison table
4. Click **Export to Excel** to download the results as an `.xlsx` file

## Deployment

The platform is deployed on Vercel:

```bash
vercel --prod
```

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **APIs**: 13 OSINT tool REST APIs
- **Excel Export**: SheetJS (xlsx library)
- **Deployment**: Vercel

## Course Info

**OSINT Course - Task 1**  
Instructor: Hilmand Khan  
Student: Khubab Ahmed

---

*All tools use free API tiers. No paid subscriptions required.*
