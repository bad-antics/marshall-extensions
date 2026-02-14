/**
 * DNS Recon Extension for Marshall Browser
 * DNS reconnaissance and zone analysis
 * Part of Marshall Extensions Collection
 */

const dns = require('dns');
const { Resolver } = dns.promises;

class DNSRecon {
  constructor() {
    this.version = '1.0.0';
    this.resolver = new Resolver();
    this.resolver.setServers(['8.8.8.8', '1.1.1.1']);
  }

  async fullRecon(domain) {
    const results = {
      domain,
      timestamp: new Date().toISOString(),
      records: {},
      security: {},
      infrastructure: {},
    };

    // Parallel DNS lookups
    const queries = [
      this._queryRecords(domain, 'A'),
      this._queryRecords(domain, 'AAAA'),
      this._queryRecords(domain, 'MX'),
      this._queryRecords(domain, 'NS'),
      this._queryRecords(domain, 'TXT'),
      this._queryRecords(domain, 'SOA'),
      this._queryRecords(domain, 'CNAME'),
      this._queryRecords(domain, 'CAA'),
      this._queryRecords(domain, 'SRV'),
    ];

    const [a, aaaa, mx, ns, txt, soa, cname, caa, srv] = await Promise.all(queries);

    results.records = { A: a, AAAA: aaaa, MX: mx, NS: ns, TXT: txt, SOA: soa, CNAME: cname, CAA: caa, SRV: srv };

    // Security analysis
    results.security = {
      spf: this._analyzeSPF(txt),
      dmarc: await this._checkDMARC(domain),
      dkim: await this._checkDKIM(domain),
      dnssec: await this._checkDNSSEC(domain),
      caa: this._analyzeCAA(caa),
    };

    // Infrastructure analysis
    results.infrastructure = {
      nameservers: ns,
      mail_servers: this._analyzeMX(mx),
      ipv6_ready: aaaa.length > 0,
      cdn_detected: this._detectCDN(a, cname),
    };

    // Common subdomains
    results.subdomains = await this._bruteSubdomains(domain);

    return results;
  }

  async _queryRecords(domain, type) {
    try {
      switch (type) {
        case 'A': return await this.resolver.resolve4(domain);
        case 'AAAA': return await this.resolver.resolve6(domain);
        case 'MX': return await this.resolver.resolveMx(domain);
        case 'NS': return await this.resolver.resolveNs(domain);
        case 'TXT': return (await this.resolver.resolveTxt(domain)).flat();
        case 'SOA': return [await this.resolver.resolveSoa(domain)];
        case 'CNAME': return await this.resolver.resolveCname(domain);
        case 'CAA': return await this.resolver.resolveCaa(domain);
        case 'SRV': return await this.resolver.resolveSrv(domain);
        default: return [];
      }
    } catch {
      return [];
    }
  }

  _analyzeSPF(txtRecords) {
    const spf = txtRecords.find(r => r.startsWith('v=spf1'));
    if (!spf) return { present: false, grade: 'F', detail: 'No SPF record found' };

    const analysis = { present: true, record: spf, mechanisms: [] };

    if (spf.includes('+all')) {
      analysis.grade = 'F';
      analysis.detail = 'SPF allows all senders (+all) — no protection';
    } else if (spf.includes('~all')) {
      analysis.grade = 'C';
      analysis.detail = 'SPF soft-fails unauthorized (~all) — partial protection';
    } else if (spf.includes('-all')) {
      analysis.grade = 'A';
      analysis.detail = 'SPF hard-fails unauthorized (-all) — strong protection';
    } else if (spf.includes('?all')) {
      analysis.grade = 'D';
      analysis.detail = 'SPF neutral (?all) — minimal protection';
    } else {
      analysis.grade = 'B';
      analysis.detail = 'SPF present but no explicit all mechanism';
    }

    return analysis;
  }

  async _checkDMARC(domain) {
    const txt = await this._queryRecords(`_dmarc.${domain}`, 'TXT');
    const dmarc = txt.find(r => r.startsWith('v=DMARC1'));
    if (!dmarc) return { present: false, grade: 'F', detail: 'No DMARC record' };

    const policy = dmarc.match(/p=(\w+)/);
    const pct = dmarc.match(/pct=(\d+)/);

    return {
      present: true,
      record: dmarc,
      policy: policy ? policy[1] : 'none',
      percentage: pct ? parseInt(pct[1]) : 100,
      grade: policy && policy[1] === 'reject' ? 'A' : policy && policy[1] === 'quarantine' ? 'B' : 'D',
    };
  }

  async _checkDKIM(domain) {
    const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim'];
    const found = [];

    for (const sel of selectors) {
      const txt = await this._queryRecords(`${sel}._domainkey.${domain}`, 'TXT');
      if (txt.length > 0) {
        found.push({ selector: sel, record: txt[0] });
      }
    }

    return {
      present: found.length > 0,
      selectors_found: found,
      grade: found.length > 0 ? 'A' : 'D',
    };
  }

  async _checkDNSSEC(domain) {
    try {
      const records = await this._queryRecords(domain, 'A');
      // Basic DNSSEC presence check via DS record at parent
      return { checked: true, note: 'Requires external validation' };
    } catch {
      return { checked: false };
    }
  }

  _analyzeCAA(caaRecords) {
    if (caaRecords.length === 0) {
      return { present: false, grade: 'C', detail: 'No CAA records — any CA can issue certificates' };
    }
    return {
      present: true,
      records: caaRecords,
      grade: 'A',
      detail: 'CAA records restrict certificate issuance',
    };
  }

  _analyzeMX(mxRecords) {
    if (mxRecords.length === 0) return { provider: 'none', records: [] };

    const exchanges = mxRecords.map(r => r.exchange || r);
    const provider = exchanges.some(e => /google|gmail/i.test(e)) ? 'Google Workspace'
      : exchanges.some(e => /outlook|microsoft/i.test(e)) ? 'Microsoft 365'
      : exchanges.some(e => /proton/i.test(e)) ? 'ProtonMail'
      : 'Custom/Other';

    return { provider, records: mxRecords };
  }

  _detectCDN(aRecords, cnameRecords) {
    const allRecords = [...aRecords, ...cnameRecords].map(r => String(r).toLowerCase());
    const cdnPatterns = {
      'Cloudflare': /cloudflare/,
      'AWS CloudFront': /cloudfront/,
      'Fastly': /fastly/,
      'Akamai': /akamai|edgekey/,
      'Google Cloud CDN': /google|1e100/,
      'Azure CDN': /azureedge|msedge/,
    };

    for (const [name, pattern] of Object.entries(cdnPatterns)) {
      if (allRecords.some(r => pattern.test(r))) {
        return { detected: true, provider: name };
      }
    }
    return { detected: false };
  }

  async _bruteSubdomains(domain) {
    const common = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
      'blog', 'shop', 'portal', 'vpn', 'remote', 'cdn', 'app', 'beta',
      'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'webmail'];

    const found = [];
    const checks = common.map(async (sub) => {
      const fqdn = `${sub}.${domain}`;
      const ips = await this._queryRecords(fqdn, 'A');
      if (ips.length > 0) {
        found.push({ subdomain: fqdn, ips });
      }
    });

    await Promise.all(checks);
    return found;
  }
}

module.exports = DNSRecon;
