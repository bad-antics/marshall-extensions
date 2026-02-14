/**
 * Privacy Report Extension for Marshall Browser
 * Comprehensive privacy analysis for visited sites
 * Part of Marshall Extensions Collection
 */

class PrivacyReport {
  constructor() {
    this.version = '1.0.0';

    this.trackerDomains = {
      'google-analytics.com': { name: 'Google Analytics', category: 'analytics' },
      'googletagmanager.com': { name: 'Google Tag Manager', category: 'analytics' },
      'facebook.net': { name: 'Facebook Pixel', category: 'advertising' },
      'doubleclick.net': { name: 'Google DoubleClick', category: 'advertising' },
      'amazon-adsystem.com': { name: 'Amazon Ads', category: 'advertising' },
      'hotjar.com': { name: 'Hotjar', category: 'session-recording' },
      'fullstory.com': { name: 'FullStory', category: 'session-recording' },
      'mixpanel.com': { name: 'Mixpanel', category: 'analytics' },
      'segment.io': { name: 'Segment', category: 'analytics' },
      'amplitude.com': { name: 'Amplitude', category: 'analytics' },
      'newrelic.com': { name: 'New Relic', category: 'monitoring' },
      'sentry.io': { name: 'Sentry', category: 'monitoring' },
      'intercom.io': { name: 'Intercom', category: 'marketing' },
      'hubspot.com': { name: 'HubSpot', category: 'marketing' },
      'clarity.ms': { name: 'Microsoft Clarity', category: 'session-recording' },
      'tiktok.com': { name: 'TikTok Pixel', category: 'advertising' },
      'snapchat.com': { name: 'Snapchat Pixel', category: 'advertising' },
      'criteo.com': { name: 'Criteo', category: 'advertising' },
    };
  }

  analyze(url, html, cookies = [], requests = [], headers = {}) {
    const report = {
      url,
      timestamp: new Date().toISOString(),
      score: 100,
      grade: 'A+',
      sections: {},
    };

    // Tracker analysis
    report.sections.trackers = this._analyzeTrackers(html, requests);
    report.score -= report.sections.trackers.count * 5;

    // Cookie analysis
    report.sections.cookies = this._analyzeCookies(cookies);
    report.score -= report.sections.cookies.thirdParty * 3;

    // Fingerprinting analysis
    report.sections.fingerprinting = this._analyzeFingerprinting(html);
    report.score -= report.sections.fingerprinting.techniques.length * 8;

    // Security headers
    report.sections.securityHeaders = this._analyzeSecurityHeaders(headers);
    report.score -= report.sections.securityHeaders.missing.length * 3;

    // Privacy policy
    report.sections.privacyPolicy = this._checkPrivacyPolicy(html);

    // Calculate grade
    report.score = Math.max(0, Math.min(100, report.score));
    report.grade = this._scoreToGrade(report.score);

    return report;
  }

  _analyzeTrackers(html, requests) {
    const found = [];
    const categories = {};

    // Check HTML for tracker scripts
    for (const [domain, info] of Object.entries(this.trackerDomains)) {
      if (html.includes(domain) || requests.some(r => r.includes(domain))) {
        found.push({ domain, ...info });
        categories[info.category] = (categories[info.category] || 0) + 1;
      }
    }

    return {
      count: found.length,
      trackers: found,
      categories,
      severity: found.length > 5 ? 'HIGH' : found.length > 2 ? 'MEDIUM' : 'LOW',
    };
  }

  _analyzeCookies(cookies) {
    let firstParty = 0;
    let thirdParty = 0;
    let session = 0;
    let persistent = 0;
    let secure = 0;
    let httpOnly = 0;
    let sameSite = 0;
    const issues = [];

    for (const cookie of cookies) {
      if (cookie.thirdParty || cookie.domain?.startsWith('.')) {
        thirdParty++;
      } else {
        firstParty++;
      }

      if (cookie.expires) persistent++; else session++;
      if (cookie.secure) secure++;
      if (cookie.httpOnly) httpOnly++;
      if (cookie.sameSite && cookie.sameSite !== 'None') sameSite++;

      // Check for tracking cookie patterns
      if (/^_ga|^_gid|^_fbp|^_fbc|^__utm/.test(cookie.name)) {
        issues.push({
          cookie: cookie.name,
          type: 'TRACKING_COOKIE',
          detail: 'Known tracking cookie identifier',
        });
      }

      // Long-lived cookies
      if (cookie.expires) {
        const expiry = new Date(cookie.expires);
        const daysUntilExpiry = (expiry - new Date()) / (1000 * 60 * 60 * 24);
        if (daysUntilExpiry > 365) {
          issues.push({
            cookie: cookie.name,
            type: 'LONG_LIVED',
            detail: `Expires in ${Math.floor(daysUntilExpiry)} days`,
          });
        }
      }
    }

    return {
      total: cookies.length,
      firstParty,
      thirdParty,
      session,
      persistent,
      secure,
      httpOnly,
      sameSite,
      issues,
    };
  }

  _analyzeFingerprinting(html) {
    const techniques = [];

    const patterns = {
      'Canvas Fingerprinting': /toDataURL|getImageData|canvas.*fingerprint/i,
      'WebGL Fingerprinting': /webgl|getParameter.*RENDERER|WEBGL_debug_renderer_info/i,
      'AudioContext': /AudioContext|createOscillator|createAnalyser/i,
      'Font Enumeration': /font.*detect|measureText.*loop|font.*fingerprint/i,
      'Navigator Properties': /navigator\.(plugins|mimeTypes|hardwareConcurrency|deviceMemory)/i,
      'Screen Properties': /screen\.(colorDepth|pixelDepth|availWidth)/i,
      'Battery API': /getBattery|BatteryManager/i,
      'WebRTC Leak': /RTCPeerConnection|createDataChannel/i,
      'Timezone Detection': /Intl\.DateTimeFormat|getTimezoneOffset/i,
      'Touch Detection': /maxTouchPoints|ontouchstart/i,
    };

    for (const [name, pattern] of Object.entries(patterns)) {
      if (pattern.test(html)) {
        techniques.push({ name, severity: 'MEDIUM' });
      }
    }

    return {
      detected: techniques.length > 0,
      techniques,
      risk: techniques.length > 4 ? 'HIGH' : techniques.length > 1 ? 'MEDIUM' : 'LOW',
    };
  }

  _analyzeSecurityHeaders(headers) {
    const required = {
      'content-security-policy': 'Prevents XSS and data injection',
      'x-content-type-options': 'Prevents MIME-type sniffing',
      'x-frame-options': 'Prevents clickjacking',
      'strict-transport-security': 'Enforces HTTPS',
      'referrer-policy': 'Controls referrer information leakage',
      'permissions-policy': 'Controls browser feature access',
      'x-xss-protection': 'Legacy XSS protection',
    };

    const present = [];
    const missing = [];
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());

    for (const [header, purpose] of Object.entries(required)) {
      if (headerKeys.includes(header)) {
        present.push({ header, value: headers[header], purpose });
      } else {
        missing.push({ header, purpose });
      }
    }

    return { present, missing };
  }

  _checkPrivacyPolicy(html) {
    const patterns = [
      /privacy.?policy/i,
      /data.?protection/i,
      /cookie.?policy/i,
      /gdpr/i,
      /ccpa/i,
      /do.?not.?sell/i,
    ];

    const found = patterns.filter(p => p.test(html)).map(p => p.source);

    return {
      hasPrivacyPolicy: found.length > 0,
      indicators: found,
      gdprCompliance: /gdpr|data.?protection|consent/i.test(html),
      ccpaCompliance: /ccpa|do.?not.?sell|california/i.test(html),
    };
  }

  _scoreToGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 75) return 'B';
    if (score >= 65) return 'C';
    if (score >= 50) return 'D';
    return 'F';
  }
}

module.exports = PrivacyReport;
