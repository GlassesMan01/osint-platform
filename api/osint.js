const axios = require('axios');
const dns = require('dns').promises;

async function resolveIP(domain) {
  try {
    const cleaned = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const addresses = await dns.resolve4(cleaned);
    return addresses[0];
  } catch {
    return null;
  }
}

function cleanDomain(target) {
  return target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
}

async function safeRequest(name, fn) {
  try {
    const data = await fn();
    return { tool: name, status: 'success', data };
  } catch (err) {
    const msg = err.response?.data?.error || err.response?.data?.message || err.message;
    return { tool: name, status: 'error', data: null, error: String(msg) };
  }
}

// 1. VirusTotal
async function queryVirusTotal(domain) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'VirusTotal', status: 'no_key', data: null };
  return safeRequest('VirusTotal', async () => {
    const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': key },
      timeout: 15000
    });
    const attrs = res.data.data?.attributes || {};
    return {
      reputation: attrs.reputation ?? 'N/A',
      categories: attrs.categories ? Object.values(attrs.categories).join(', ') : 'N/A',
      last_analysis_stats: attrs.last_analysis_stats || {},
      registrar: attrs.registrar || 'N/A',
      creation_date: attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString().split('T')[0] : 'N/A',
      last_update: attrs.last_modification_date ? new Date(attrs.last_modification_date * 1000).toISOString().split('T')[0] : 'N/A',
      dns_records: (attrs.last_dns_records || []).slice(0, 5).map(r => `${r.type}: ${r.value}`).join('; ') || 'N/A'
    };
  });
}

// 2. Shodan
async function queryShodan(domain, ip) {
  const key = process.env.SHODAN_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'Shodan', status: 'no_key', data: null };
  const targetIP = ip || domain;
  return safeRequest('Shodan', async () => {
    const res = await axios.get(`https://api.shodan.io/shodan/host/${targetIP}?key=${key}`, { timeout: 15000 });
    return {
      ip: res.data.ip_str || targetIP,
      organization: res.data.org || 'N/A',
      os: res.data.os || 'N/A',
      open_ports: (res.data.ports || []).join(', ') || 'N/A',
      isp: res.data.isp || 'N/A',
      country: res.data.country_name || 'N/A',
      city: res.data.city || 'N/A',
      vulns: (res.data.vulns || []).slice(0, 5).join(', ') || 'None found',
      hostnames: (res.data.hostnames || []).join(', ') || 'N/A'
    };
  });
}

// 3. SecurityTrails
async function querySecurityTrails(domain) {
  const key = process.env.SECURITYTRAILS_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'SecurityTrails', status: 'no_key', data: null };
  return safeRequest('SecurityTrails', async () => {
    const res = await axios.get(`https://api.securitytrails.com/v1/domain/${domain}`, {
      headers: { APIKEY: key },
      timeout: 15000
    });
    const rec = res.data.current_dns || {};
    return {
      hostname: res.data.hostname || domain,
      a_records: (rec.a?.values || []).map(v => v.ip).join(', ') || 'N/A',
      mx_records: (rec.mx?.values || []).map(v => v.hostname).join(', ') || 'N/A',
      ns_records: (rec.ns?.values || []).map(v => v.nameserver).join(', ') || 'N/A',
      soa_email: rec.soa?.values?.[0]?.email || 'N/A',
      alexa_rank: res.data.alexa_rank || 'N/A'
    };
  });
}

// 4. IPinfo
async function queryIPinfo(domain, ip) {
  const key = process.env.IPINFO_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'IPinfo', status: 'no_key', data: null };
  const targetIP = ip || domain;
  return safeRequest('IPinfo', async () => {
    const res = await axios.get(`https://ipinfo.io/${targetIP}?token=${key}`, { timeout: 15000 });
    return {
      ip: res.data.ip || targetIP,
      hostname: res.data.hostname || 'N/A',
      city: res.data.city || 'N/A',
      region: res.data.region || 'N/A',
      country: res.data.country || 'N/A',
      location: res.data.loc || 'N/A',
      organization: res.data.org || 'N/A',
      timezone: res.data.timezone || 'N/A'
    };
  });
}

// 5. AbuseIPDB
async function queryAbuseIPDB(ip) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'AbuseIPDB', status: 'no_key', data: null };
  if (!ip) return { tool: 'AbuseIPDB', status: 'error', data: null, error: 'Could not resolve IP' };
  return safeRequest('AbuseIPDB', async () => {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: key, Accept: 'application/json' },
      timeout: 15000
    });
    const d = res.data.data || {};
    return {
      ip_address: d.ipAddress || ip,
      is_public: d.isPublic ?? 'N/A',
      abuse_confidence_score: d.abuseConfidenceScore ?? 'N/A',
      total_reports: d.totalReports ?? 'N/A',
      country_code: d.countryCode || 'N/A',
      isp: d.isp || 'N/A',
      domain: d.domain || 'N/A',
      usage_type: d.usageType || 'N/A',
      is_tor: d.isTor ?? 'N/A'
    };
  });
}

// 6. URLScan.io
async function queryURLScan(domain) {
  const key = process.env.URLSCAN_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'URLScan.io', status: 'no_key', data: null };
  return safeRequest('URLScan.io', async () => {
    const submitRes = await axios.post('https://urlscan.io/api/v1/scan/', {
      url: `https://${domain}`,
      visibility: 'public'
    }, {
      headers: { 'API-Key': key, 'Content-Type': 'application/json' },
      timeout: 15000
    });
    const uuid = submitRes.data.uuid;
    await new Promise(r => setTimeout(r, 12000));
    const resultRes = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`, { timeout: 15000 });
    const page = resultRes.data.page || {};
    const stats = resultRes.data.stats || {};
    return {
      url: page.url || `https://${domain}`,
      domain: page.domain || domain,
      ip: page.ip || 'N/A',
      country: page.country || 'N/A',
      server: page.server || 'N/A',
      title: page.title || 'N/A',
      status_code: page.status || 'N/A',
      tls_issuer: resultRes.data.lists?.certificates?.[0]?.issuer || 'N/A',
      total_links: stats.totalLinks ?? 'N/A',
      technologies: (resultRes.data.meta?.processors?.wappa?.data || []).slice(0, 5).map(t => t.app).join(', ') || 'N/A'
    };
  });
}

// 7. WhoisXML API
async function queryWhoisXML(domain) {
  const key = process.env.WHOISXML_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'WhoisXML', status: 'no_key', data: null };
  return safeRequest('WhoisXML', async () => {
    const res = await axios.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
      params: { apiKey: key, domainName: domain, outputFormat: 'JSON' },
      timeout: 15000
    });
    const rec = res.data.WhoisRecord || {};
    return {
      domain_name: rec.domainName || domain,
      registrar: rec.registrarName || 'N/A',
      created_date: rec.createdDate || 'N/A',
      updated_date: rec.updatedDate || 'N/A',
      expires_date: rec.expiresDate || 'N/A',
      registrant_country: rec.registrant?.country || 'N/A',
      registrant_org: rec.registrant?.organization || 'N/A',
      name_servers: (rec.nameServers?.hostNames || []).join(', ') || 'N/A',
      status: (rec.status || '').substring(0, 100) || 'N/A'
    };
  });
}

// 8. AlienVault OTX
async function queryAlienVault(domain) {
  const key = process.env.ALIENVAULT_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'AlienVault OTX', status: 'no_key', data: null };
  return safeRequest('AlienVault OTX', async () => {
    const general = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, {
      headers: { 'X-OTX-API-KEY': key },
      timeout: 15000
    });
    const geo = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/geo`, {
      headers: { 'X-OTX-API-KEY': key },
      timeout: 15000
    });
    const gd = general.data || {};
    const geoData = geo.data || {};
    return {
      pulse_count: gd.pulse_info?.count ?? 0,
      reputation: gd.reputation ?? 'N/A',
      alexa_rank: gd.alexa || 'N/A',
      whois_registrar: gd.whois?.registrar || 'N/A',
      country: geoData.country_name || 'N/A',
      city: geoData.city || 'N/A',
      asn: geoData.asn || 'N/A',
      related_pulses: (gd.pulse_info?.pulses || []).slice(0, 3).map(p => p.name).join('; ') || 'None'
    };
  });
}

// 9. GreyNoise
async function queryGreyNoise(ip) {
  const key = process.env.GREYNOISE_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'GreyNoise', status: 'no_key', data: null };
  if (!ip) return { tool: 'GreyNoise', status: 'error', data: null, error: 'Could not resolve IP' };
  return safeRequest('GreyNoise', async () => {
    const res = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: { key: key },
      timeout: 15000
    });
    return {
      ip: res.data.ip || ip,
      noise: res.data.noise ?? 'N/A',
      riot: res.data.riot ?? 'N/A',
      classification: res.data.classification || 'N/A',
      name: res.data.name || 'N/A',
      link: res.data.link || 'N/A',
      last_seen: res.data.last_seen || 'N/A',
      message: res.data.message || 'N/A'
    };
  });
}

// 10. Hunter.io
async function queryHunter(domain) {
  const key = process.env.HUNTER_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'Hunter.io', status: 'no_key', data: null };
  return safeRequest('Hunter.io', async () => {
    const res = await axios.get('https://api.hunter.io/v2/domain-search', {
      params: { domain, api_key: key },
      timeout: 15000
    });
    const d = res.data.data || {};
    return {
      domain: d.domain || domain,
      organization: d.organization || 'N/A',
      email_pattern: d.pattern || 'N/A',
      emails_found: d.emails?.length ?? 0,
      sample_emails: (d.emails || []).slice(0, 5).map(e => e.value).join(', ') || 'N/A',
      department_breakdown: d.departments ? Object.entries(d.departments).filter(([,v]) => v > 0).map(([k,v]) => `${k}: ${v}`).join(', ') : 'N/A',
      technologies: (d.technologies || []).join(', ') || 'N/A'
    };
  });
}

async function analyzeTarget(target) {
  const domain = cleanDomain(target);
  const ip = await resolveIP(domain);

  const results = await Promise.allSettled([
    queryVirusTotal(domain),
    queryShodan(domain, ip),
    querySecurityTrails(domain),
    queryIPinfo(domain, ip),
    queryAbuseIPDB(ip),
    queryURLScan(domain),
    queryWhoisXML(domain),
    queryAlienVault(domain),
    queryGreyNoise(ip),
    queryHunter(domain)
  ]);

  return results.map(r => {
    if (r.status === 'fulfilled') return r.value;
    return { tool: 'Unknown', status: 'error', data: null, error: r.reason?.message };
  });
}

module.exports = { analyzeTarget };
