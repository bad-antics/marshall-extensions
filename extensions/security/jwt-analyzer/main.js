/**
 * JWT Analyzer Extension for Marshall Browser
 * Decode, analyze, and test JWT tokens for security vulnerabilities
 * Part of Marshall Extensions Collection
 */

class JWTAnalyzer {
  constructor() {
    this.version = '1.0.0';
    this.weakAlgorithms = ['none', 'HS256', 'HS384', 'HS512'];
    this.strongAlgorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA'];
  }

  decode(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { error: 'Invalid JWT format — expected 3 parts' };
    }

    try {
      const header = JSON.parse(this._base64Decode(parts[0]));
      const payload = JSON.parse(this._base64Decode(parts[1]));
      const signature = parts[2];

      return {
        raw: token,
        header,
        payload,
        signature,
        analysis: this._analyze(header, payload, signature),
      };
    } catch (e) {
      return { error: `Decode failed: ${e.message}` };
    }
  }

  _base64Decode(str) {
    const padded = str + '='.repeat((4 - str.length % 4) % 4);
    return Buffer.from(padded, 'base64url').toString('utf-8');
  }

  _analyze(header, payload, signature) {
    const issues = [];
    const info = [];

    // Algorithm analysis
    const alg = header.alg || 'UNKNOWN';
    if (alg === 'none') {
      issues.push({
        severity: 'CRITICAL',
        title: 'Algorithm: none',
        detail: 'Token uses no signature algorithm — can be freely forged',
      });
    } else if (this.weakAlgorithms.includes(alg)) {
      issues.push({
        severity: 'MEDIUM',
        title: `Symmetric algorithm: ${alg}`,
        detail: 'HMAC-based algorithms are vulnerable to key confusion attacks against RS* implementations',
      });
    } else if (this.strongAlgorithms.includes(alg)) {
      info.push({ title: `Strong algorithm: ${alg}`, detail: 'Asymmetric signing is recommended' });
    }

    // Key ID check
    if (!header.kid) {
      issues.push({
        severity: 'LOW',
        title: 'No Key ID (kid)',
        detail: 'Missing kid header makes key rotation harder to manage',
      });
    }

    // JWKS URI injection
    if (header.jku) {
      issues.push({
        severity: 'HIGH',
        title: 'JKU header present',
        detail: `Token references external JWKS URI: ${header.jku} — potential SSRF/key injection`,
      });
    }
    if (header.x5u) {
      issues.push({
        severity: 'HIGH',
        title: 'X5U header present',
        detail: 'Token references external X.509 URL — potential key injection',
      });
    }

    // Expiration analysis
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp) {
      if (payload.exp < now) {
        issues.push({
          severity: 'INFO',
          title: 'Token expired',
          detail: `Expired ${new Date(payload.exp * 1000).toISOString()}`,
        });
      } else {
        const ttl = payload.exp - now;
        if (ttl > 86400 * 30) {
          issues.push({
            severity: 'MEDIUM',
            title: 'Long-lived token',
            detail: `Token valid for ${Math.floor(ttl / 86400)} days — consider shorter expiry`,
          });
        }
        info.push({
          title: 'Expires',
          detail: `${new Date(payload.exp * 1000).toISOString()} (${Math.floor(ttl / 3600)}h remaining)`,
        });
      }
    } else {
      issues.push({
        severity: 'HIGH',
        title: 'No expiration (exp)',
        detail: 'Token never expires — can be used indefinitely if compromised',
      });
    }

    // Issued at
    if (payload.iat) {
      info.push({
        title: 'Issued at',
        detail: new Date(payload.iat * 1000).toISOString(),
      });
    }

    // Not before
    if (payload.nbf && payload.nbf > now) {
      info.push({
        title: 'Not valid yet',
        detail: `Valid from ${new Date(payload.nbf * 1000).toISOString()}`,
      });
    }

    // Audience and issuer
    if (!payload.iss) {
      issues.push({
        severity: 'LOW',
        title: 'No issuer (iss)',
        detail: 'Missing issuer claim makes token origin validation impossible',
      });
    }
    if (!payload.aud) {
      issues.push({
        severity: 'LOW',
        title: 'No audience (aud)',
        detail: 'Missing audience claim — token may be reusable across services',
      });
    }

    // Sensitive data in payload
    const sensitiveKeys = ['password', 'secret', 'key', 'ssn', 'credit_card', 'cc_number'];
    for (const key of Object.keys(payload)) {
      if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
        issues.push({
          severity: 'CRITICAL',
          title: `Sensitive data in payload: ${key}`,
          detail: 'JWT payloads are base64-encoded, NOT encrypted — sensitive data is exposed',
        });
      }
    }

    // Empty signature check
    if (!signature || signature === '') {
      issues.push({
        severity: 'CRITICAL',
        title: 'Empty signature',
        detail: 'Token has no signature — completely unverified',
      });
    }

    // Grade
    const criticals = issues.filter(i => i.severity === 'CRITICAL').length;
    const highs = issues.filter(i => i.severity === 'HIGH').length;
    const mediums = issues.filter(i => i.severity === 'MEDIUM').length;

    let grade = 'A';
    if (criticals > 0) grade = 'F';
    else if (highs > 0) grade = 'D';
    else if (mediums > 0) grade = 'C';
    else if (issues.length > 2) grade = 'B';

    return {
      grade,
      algorithm: alg,
      issues,
      info,
      claims: Object.keys(payload),
    };
  }

  /**
   * Test for 'alg: none' vulnerability
   */
  forgeNoneAlg(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(this._base64Decode(parts[0]));
    header.alg = 'none';

    const newHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    return `${newHeader}.${parts[1]}.`;
  }

  /**
   * Extract all JWTs from a page's cookies, localStorage, headers
   */
  extractTokens(cookies = '', localStorage = {}, headers = {}) {
    const tokens = [];
    const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

    // From cookies
    const cookieMatches = cookies.match(jwtPattern) || [];
    cookieMatches.forEach(t => tokens.push({ source: 'cookie', token: t }));

    // From localStorage
    for (const [key, value] of Object.entries(localStorage)) {
      const matches = String(value).match(jwtPattern) || [];
      matches.forEach(t => tokens.push({ source: `localStorage:${key}`, token: t }));
    }

    // From headers
    for (const [key, value] of Object.entries(headers)) {
      const matches = String(value).match(jwtPattern) || [];
      matches.forEach(t => tokens.push({ source: `header:${key}`, token: t }));
    }

    return tokens.map(t => ({
      ...t,
      decoded: this.decode(t.token),
    }));
  }
}

module.exports = JWTAnalyzer;
