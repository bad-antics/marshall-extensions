/**
 * CORS Scanner Extension for Marshall Browser
 * Detect CORS misconfigurations and insecure cross-origin policies
 * Part of Marshall Extensions Collection
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

class CORSScanner {
  constructor() {
    this.version = '1.0.0';
    this.results = [];
  }

  /**
   * Test a URL for CORS misconfigurations
   */
  async scan(targetUrl) {
    const url = new URL(targetUrl);
    const results = {
      url: targetUrl,
      timestamp: new Date().toISOString(),
      tests: [],
      severity: 'INFO',
      grade: 'A',
    };

    // Test 1: Reflect arbitrary origin
    const arbitraryOrigin = await this._testOrigin(url, 'https://evil.com');
    results.tests.push({
      name: 'Arbitrary Origin Reflection',
      ...arbitraryOrigin,
    });

    // Test 2: Null origin
    const nullOrigin = await this._testOrigin(url, 'null');
    results.tests.push({
      name: 'Null Origin Accepted',
      ...nullOrigin,
    });

    // Test 3: Subdomain wildcard
    const subdomainOrigin = await this._testOrigin(
      url, `https://evil.${url.hostname}`
    );
    results.tests.push({
      name: 'Subdomain Bypass',
      ...subdomainOrigin,
    });

    // Test 4: Prefix match bypass
    const prefixOrigin = await this._testOrigin(
      url, `https://${url.hostname}.evil.com`
    );
    results.tests.push({
      name: 'Prefix Match Bypass',
      ...prefixOrigin,
    });

    // Test 5: HTTP downgrade
    if (url.protocol === 'https:') {
      const httpOrigin = await this._testOrigin(
        url, `http://${url.hostname}`
      );
      results.tests.push({
        name: 'HTTP Downgrade',
        ...httpOrigin,
      });
    }

    // Test 6: Credentials with wildcard
    const credTest = await this._testCredentials(url);
    results.tests.push({
      name: 'Credentials with Wildcard',
      ...credTest,
    });

    // Calculate severity
    const vulnTests = results.tests.filter(t => t.vulnerable);
    if (vulnTests.length >= 3) {
      results.severity = 'CRITICAL';
      results.grade = 'F';
    } else if (vulnTests.length >= 2) {
      results.severity = 'HIGH';
      results.grade = 'D';
    } else if (vulnTests.length === 1) {
      results.severity = 'MEDIUM';
      results.grade = 'C';
    }

    this.results.push(results);
    return results;
  }

  async _testOrigin(url, origin) {
    return new Promise((resolve) => {
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'OPTIONS',
        headers: {
          'Origin': origin,
          'Access-Control-Request-Method': 'GET',
          'User-Agent': 'Marshall-Browser/1.0 CORS-Scanner',
        },
        timeout: 5000,
      };

      const proto = url.protocol === 'https:' ? https : http;
      const req = proto.request(options, (res) => {
        const acao = res.headers['access-control-allow-origin'] || '';
        const acac = res.headers['access-control-allow-credentials'] || '';
        const acam = res.headers['access-control-allow-methods'] || '';

        const reflected = acao === origin || acao === '*';
        const withCreds = acac.toLowerCase() === 'true';

        resolve({
          vulnerable: reflected,
          origin_sent: origin,
          acao_returned: acao,
          credentials: withCreds,
          methods: acam,
          detail: reflected
            ? `Origin '${origin}' is reflected — potential CORS bypass`
            : 'Origin not reflected',
        });
      });

      req.on('error', () => resolve({ vulnerable: false, error: 'Connection failed' }));
      req.on('timeout', () => { req.destroy(); resolve({ vulnerable: false, error: 'Timeout' }); });
      req.end();
    });
  }

  async _testCredentials(url) {
    return new Promise((resolve) => {
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'GET',
        headers: {
          'Origin': 'https://evil.com',
          'User-Agent': 'Marshall-Browser/1.0 CORS-Scanner',
        },
        timeout: 5000,
      };

      const proto = url.protocol === 'https:' ? https : http;
      const req = proto.request(options, (res) => {
        const acao = res.headers['access-control-allow-origin'] || '';
        const acac = res.headers['access-control-allow-credentials'] || '';

        const wildcard = acao === '*';
        const withCreds = acac.toLowerCase() === 'true';

        resolve({
          vulnerable: wildcard && withCreds,
          acao: acao,
          credentials: withCreds,
          detail: wildcard && withCreds
            ? 'CRITICAL: Wildcard origin with credentials — full CORS bypass'
            : 'Credentials/wildcard combination is safe',
        });
      });

      req.on('error', () => resolve({ vulnerable: false, error: 'Connection failed' }));
      req.on('timeout', () => { req.destroy(); resolve({ vulnerable: false, error: 'Timeout' }); });
      req.end();
    });
  }

  getReport() {
    return {
      scanner: 'Marshall CORS Scanner',
      version: this.version,
      total_scans: this.results.length,
      results: this.results,
    };
  }
}

module.exports = CORSScanner;
