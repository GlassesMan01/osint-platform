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
    const raw = err.response?.data?.error || err.response?.data?.message || err.response?.data || err.message;
    const msg = typeof raw === 'object' ? JSON.stringify(raw) : String(raw);
    return { tool: name, status: 'error', data: null, error: `Status ${err.response?.status || 'unknown'}: ${msg}`.substring(0, 200) };
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

// 3. IPinfo
async function queryIPinfo(domain, ip) {
  const key = process.env.IPINFO_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'IPinfo', status: 'no_key', data: null };
  const targetIP = ip || domain;
  return safeRequest('IPinfo', async () => {
    const res = await axios.get(`https://ipinfo.io/${targetIP}/json?token=${key}`, { timeout: 15000 });
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

// 4. AbuseIPDB
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

// 5. URLScan.io
async function queryURLScan(domain) {
  const key = process.env.URLSCAN_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'URLScan.io', status: 'no_key', data: null };
  return safeRequest('URLScan.io', async () => {
    const searchRes = await axios.get(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1`, {
      headers: { 'API-Key': key },
      timeout: 15000
    });
    if (searchRes.data.results?.length > 0) {
      const latest = searchRes.data.results[0];
      return {
        url: latest.page?.url || `https://${domain}`,
        domain: latest.page?.domain || domain,
        ip: latest.page?.ip || 'N/A',
        country: latest.page?.country || 'N/A',
        server: latest.page?.server || 'N/A',
        title: latest.page?.title || 'N/A',
        status_code: latest.page?.status || 'N/A',
        scan_id: latest._id || 'N/A',
        scan_time: latest.task?.time || 'N/A'
      };
    }
    const submitRes = await axios.post('https://urlscan.io/api/v1/scan/', {
      url: `https://${domain}`, visibility: 'public'
    }, {
      headers: { 'API-Key': key, 'Content-Type': 'application/json' },
      timeout: 15000
    });
    return {
      message: 'Scan submitted',
      uuid: submitRes.data.uuid || 'N/A',
      url: submitRes.data.api || 'N/A',
      visibility: submitRes.data.visibility || 'public',
      result_url: submitRes.data.result || 'N/A'
    };
  });
}

// 6. AlienVault OTX
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

// 7. GreyNoise
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

// 8. Censys
async function queryCensys(ip) {
  const key = process.env.CENSYS_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'Censys', status: 'no_key', data: null };
  if (!ip) return { tool: 'Censys', status: 'error', data: null, error: 'Could not resolve IP' };
  return safeRequest('Censys', async () => {
    const res = await axios.get(`https://search.censys.io/api/v2/hosts/${ip}`, {
      headers: { Authorization: `Bearer ${key}` },
      timeout: 15000
    });
    const host = res.data.result || {};
    const services = host.services || [];
    return {
      ip: host.ip || ip,
      country: host.location?.country || 'N/A',
      city: host.location?.city || 'N/A',
      asn: host.autonomous_system?.asn || 'N/A',
      as_name: host.autonomous_system?.name || 'N/A',
      as_description: host.autonomous_system?.description || 'N/A',
      open_services: services.map(s => `${s.port}/${s.transport_protocol} (${s.service_name || 'unknown'})`).join(', ') || 'N/A',
      os: host.operating_system?.product || 'N/A',
      last_updated: host.last_updated_at || 'N/A'
    };
  });
}

// 9. ViewDNS
async function queryViewDNS(domain) {
  const key = process.env.VIEWDNS_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'ViewDNS', status: 'no_key', data: null };
  return safeRequest('ViewDNS', async () => {
    const dnsInfo = await axios.get(`https://api.viewdns.info/dnsrecord/?domain=${domain}&recordtype=ANY&apikey=${key}&output=json`, { timeout: 15000 });
    const records = dnsInfo.data?.response?.records || [];

    let ipHist = {};
    try {
      const histRes = await axios.get(`https://api.viewdns.info/iphistory/?domain=${domain}&apikey=${key}&output=json`, { timeout: 15000 });
      const recs = histRes.data?.response?.records || [];
      ipHist = {
        ip_history: recs.slice(0, 5).map(r => `${r.ip} (${r.lastresolved || 'N/A'})`).join('; ') || 'N/A'
      };
    } catch { ipHist = { ip_history: 'N/A' }; }

    return {
      dns_records: records.slice(0, 8).map(r => `${r.type}: ${r.data} (TTL: ${r.ttl})`).join('; ') || 'N/A',
      record_count: records.length,
      a_records: records.filter(r => r.type === 'A').map(r => r.data).join(', ') || 'N/A',
      mx_records: records.filter(r => r.type === 'MX').map(r => r.data).join(', ') || 'N/A',
      ns_records: records.filter(r => r.type === 'NS').map(r => r.data).join(', ') || 'N/A',
      txt_records: records.filter(r => r.type === 'TXT').map(r => r.data).join(', ') || 'N/A',
      ...ipHist
    };
  });
}

// 10. DNSdumpster
async function queryDNSdumpster(domain) {
  const key = process.env.DNSDUMPSTER_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'DNSdumpster', status: 'no_key', data: null };
  return safeRequest('DNSdumpster', async () => {
    const res = await axios.get(`https://api.dnsdumpster.com/domain/${domain}`, {
      headers: { 'X-API-Key': key },
      timeout: 15000
    });
    const d = res.data || {};
    return {
      domain: d.domain || domain,
      a_records: (d.a || []).slice(0, 5).map(r => `${r.host}: ${r.ip} (${r.provider || 'N/A'})`).join('; ') || 'N/A',
      mx_records: (d.mx || []).slice(0, 5).map(r => `${r.host} (${r.provider || 'N/A'})`).join('; ') || 'N/A',
      ns_records: (d.ns || []).slice(0, 5).map(r => `${r.host} (${r.provider || 'N/A'})`).join('; ') || 'N/A',
      txt_records: (d.txt || []).slice(0, 3).join('; ') || 'N/A',
      total_subdomains: (d.a || []).length,
      status: d.status || 'N/A'
    };
  });
}

// 11. Cloudflare Radar (no key needed)
async function queryCloudflareRadar(domain) {
  return safeRequest('Cloudflare Radar', async () => {
    const res = await axios.get(`https://radar.cloudflare.com/api/domains/${domain}`, { timeout: 15000 });
    const d = res.data || {};
    return {
      domain: domain,
      top_rank: d.rank || 'N/A',
      category: d.contentCategories?.join(', ') || 'N/A',
      popularity_rank: d.popularityRank || 'N/A',
      risk_score: d.riskScore || 'N/A',
      risk_types: (d.riskTypes || []).join(', ') || 'None',
      is_probably_safe: d.isProbablySafe ?? 'N/A',
      content_categories: (d.contentCategories || []).join(', ') || 'N/A'
    };
  });
}

// 12. LeakIX
async function queryLeakIX(ip) {
  const key = process.env.LEAKIX_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'LeakIX', status: 'no_key', data: null };
  if (!ip) return { tool: 'LeakIX', status: 'error', data: null, error: 'Could not resolve IP' };
  return safeRequest('LeakIX', async () => {
    const res = await axios.get(`https://leakix.net/host/${ip}`, {
      headers: { 'api-key': key, Accept: 'application/json' },
      timeout: 15000
    });
    const d = res.data || {};
    const services = d.Services || [];
    const leaks = d.Leaks || [];
    return {
      ip: ip,
      total_services: services.length,
      total_leaks: leaks.length,
      services_found: services.slice(0, 5).map(s => `${s.port}/${s.protocol} - ${s.service?.software?.name || 'unknown'}`).join('; ') || 'None',
      leaks_summary: leaks.slice(0, 3).map(l => `${l.type_name || 'unknown'} (${l.severity || 'N/A'})`).join('; ') || 'None found',
      country: services[0]?.geoip?.country_name || 'N/A',
      asn: services[0]?.network?.asn || 'N/A',
      organization: services[0]?.network?.organization_name || 'N/A'
    };
  });
}

// 13. Pulsedive
async function queryPulsedive(domain) {
  const key = process.env.PULSEDIVE_API_KEY;
  if (!key || key === 'your_key_here') return { tool: 'Pulsedive', status: 'no_key', data: null };
  return safeRequest('Pulsedive', async () => {
    const res = await axios.get('https://pulsedive.com/api/info.php', {
      params: { indicator: domain, key: key },
      timeout: 15000
    });
    const d = res.data || {};
    return {
      indicator: d.indicator || domain,
      type: d.type || 'N/A',
      risk: d.risk || 'N/A',
      risk_recommended: d.risk_recommended || 'N/A',
      threats: (d.threats || []).slice(0, 5).map(t => t.name || t).join(', ') || 'None',
      feeds: (d.feeds || []).slice(0, 5).map(f => f.name || f).join(', ') || 'None',
      technology: (d.attributes?.technology || []).join(', ') || 'N/A',
      port: (d.attributes?.port || []).join(', ') || 'N/A',
      protocol: (d.attributes?.protocol || []).join(', ') || 'N/A'
    };
  });
}

async function analyzeTarget(target) {
  const domain = cleanDomain(target);
  const ip = await resolveIP(domain);

  const results = await Promise.allSettled([
    queryVirusTotal(domain),
    queryShodan(domain, ip),
    queryIPinfo(domain, ip),
    queryAbuseIPDB(ip),
    queryURLScan(domain),
    queryAlienVault(domain),
    queryGreyNoise(ip),
    queryCensys(ip),
    queryViewDNS(domain),
    queryDNSdumpster(domain),
    queryCloudflareRadar(domain),
    queryLeakIX(ip),
    queryPulsedive(domain)
  ]);

  return results.map(r => {
    if (r.status === 'fulfilled') return r.value;
    return { tool: 'Unknown', status: 'error', data: null, error: r.reason?.message };
  });
}

module.exports = { analyzeTarget };
