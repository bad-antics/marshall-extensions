/**
 * Link Analyzer Extension for Marshall Browser
 * Analyze URLs for threats before visiting
 * Part of Marshall Extensions Collection
 */

class LinkAnalyzer {
    constructor() {
        this.suspiciousPatterns = {
            phishing: [
                /login.*(?:paypal|apple|microsoft|google|facebook|amazon)/i,
                /(?:paypal|apple|microsoft|google|facebook|amazon).*login/i,
                /secure.*(?:bank|account|verify)/i,
                /(?:update|verify|confirm).*(?:account|payment|card)/i,
                /\.(?:tk|ml|ga|cf|gq)\/?$/i,
                /(?:0|o)(?:0|o)(?:0|o)/i,  // character substitution
                /-(?:login|secure|account|verify)/i
            ],
            shorteners: [
                /bit\.ly/i, /tinyurl\.com/i, /t\.co/i, /goo\.gl/i,
                /ow\.ly/i, /is\.gd/i, /buff\.ly/i, /adf\.ly/i,
                /tiny\.cc/i, /rb\.gy/i, /cutt\.ly/i, /shorturl\.at/i
            ],
            suspicious_tlds: [
                '.xyz', '.top', '.work', '.date', '.racing', '.win',
                '.stream', '.gdn', '.men', '.loan', '.download', '.click'
            ],
            encoded: [
                /%[0-9a-f]{2}/gi,  // URL encoded chars
                /\\x[0-9a-f]{2}/gi  // Hex encoded
            ]
        };

        this.knownMalicious = new Set([
            // Would be populated from threat feeds
        ]);
    }

    async init() {
        marshall.contextMenu.register({
            id: 'analyze-link',
            title: '🔍 Analyze Link',
            contexts: ['link'],
            onclick: (info) => this.analyzeLink(info.linkUrl)
        });

        marshall.contextMenu.register({
            id: 'analyze-selection',
            title: '🔍 Analyze Selected URL',
            contexts: ['selection'],
            onclick: (info) => this.analyzeLink(info.selectionText)
        });

        marshall.keyboard.register('Ctrl+Shift+L', () => this.showAnalyzer());

        console.log('[Link Analyzer] Extension initialized');
        return true;
    }

    parseUrl(urlString) {
        try {
            // Handle URLs without protocol
            if (!urlString.match(/^https?:\/\//i)) {
                urlString = 'https://' + urlString;
            }
            const url = new URL(urlString);
            return {
                original: urlString,
                protocol: url.protocol,
                hostname: url.hostname,
                port: url.port,
                pathname: url.pathname,
                search: url.search,
                hash: url.hash,
                domain: this.extractDomain(url.hostname),
                subdomain: this.extractSubdomain(url.hostname),
                tld: this.extractTLD(url.hostname),
                params: Object.fromEntries(url.searchParams),
                valid: true
            };
        } catch (e) {
            return { original: urlString, valid: false, error: e.message };
        }
    }

    extractDomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    extractSubdomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length > 2) {
            return parts.slice(0, -2).join('.');
        }
        return '';
    }

    extractTLD(hostname) {
        const parts = hostname.split('.');
        return '.' + parts[parts.length - 1];
    }

    checkPatterns(url) {
        const findings = [];
        const urlString = url.original.toLowerCase();

        // Check phishing patterns
        for (const pattern of this.suspiciousPatterns.phishing) {
            if (pattern.test(urlString)) {
                findings.push({
                    type: 'phishing',
                    severity: 'high',
                    message: 'URL matches known phishing pattern',
                    pattern: pattern.toString()
                });
            }
        }

        // Check for URL shorteners
        for (const pattern of this.suspiciousPatterns.shorteners) {
            if (pattern.test(urlString)) {
                findings.push({
                    type: 'shortener',
                    severity: 'medium',
                    message: 'URL uses a link shortening service',
                    pattern: pattern.toString()
                });
            }
        }

        // Check suspicious TLDs
        for (const tld of this.suspiciousPatterns.suspicious_tlds) {
            if (url.tld === tld) {
                findings.push({
                    type: 'suspicious_tld',
                    severity: 'medium',
                    message: `Uses suspicious TLD: ${tld}`,
                    pattern: tld
                });
            }
        }

        // Check for URL encoding tricks
        const encodedMatches = urlString.match(this.suspiciousPatterns.encoded[0]);
        if (encodedMatches && encodedMatches.length > 5) {
            findings.push({
                type: 'encoding',
                severity: 'medium',
                message: 'URL contains excessive encoded characters',
                count: encodedMatches.length
            });
        }

        // Check for IP address instead of domain
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) {
            findings.push({
                type: 'ip_address',
                severity: 'medium',
                message: 'URL uses IP address instead of domain name'
            });
        }

        // Check for homograph attacks (mixed scripts)
        if (/[^\x00-\x7F]/.test(url.hostname)) {
            findings.push({
                type: 'homograph',
                severity: 'high',
                message: 'URL contains non-ASCII characters (possible homograph attack)'
            });
        }

        // Check for @ symbol (credential harvesting)
        if (url.original.includes('@') && !url.original.includes('mailto:')) {
            findings.push({
                type: 'credential_trick',
                severity: 'high',
                message: 'URL contains @ symbol (possible credential phishing)'
            });
        }

        // Check for excessive subdomains
        if (url.subdomain && url.subdomain.split('.').length > 3) {
            findings.push({
                type: 'subdomain_abuse',
                severity: 'low',
                message: 'URL has many subdomain levels'
            });
        }

        // Check for suspicious port
        if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) {
            findings.push({
                type: 'unusual_port',
                severity: 'low',
                message: `Unusual port: ${url.port}`
            });
        }

        return findings;
    }

    async checkReputation(url) {
        const checks = [];

        // Google Safe Browsing (would need API key)
        // VirusTotal (would need API key)
        // For now, we'll simulate with basic checks

        try {
            // Check if domain resolves
            const response = await marshall.network.fetch(`https://dns.google/resolve?name=${url.hostname}&type=A`, {
                timeout: 5000
            });
            const data = await response.json();
            
            if (data.Status === 0 && data.Answer) {
                checks.push({
                    service: 'DNS',
                    status: 'resolved',
                    result: `Resolves to ${data.Answer[0].data}`,
                    safe: true
                });
            } else {
                checks.push({
                    service: 'DNS',
                    status: 'failed',
                    result: 'Domain does not resolve',
                    safe: false
                });
            }
        } catch (e) {
            checks.push({
                service: 'DNS',
                status: 'error',
                result: e.message,
                safe: null
            });
        }

        // Check domain age via WHOIS (simulated)
        checks.push({
            service: 'Domain Age',
            status: 'unknown',
            result: 'Check WHOIS for registration date',
            safe: null
        });

        return checks;
    }

    async expandShortUrl(url) {
        try {
            const response = await marshall.network.fetch(url.original, {
                method: 'HEAD',
                redirect: 'manual',
                timeout: 5000
            });

            if (response.status >= 300 && response.status < 400) {
                const location = response.headers.get('location');
                if (location && location !== url.original) {
                    return {
                        expanded: true,
                        destination: location,
                        chain: [url.original, location]
                    };
                }
            }
            return { expanded: false };
        } catch (e) {
            return { expanded: false, error: e.message };
        }
    }

    calculateRiskScore(findings) {
        let score = 0;
        
        for (const finding of findings) {
            switch (finding.severity) {
                case 'high': score += 30; break;
                case 'medium': score += 15; break;
                case 'low': score += 5; break;
            }
        }

        return Math.min(100, score);
    }

    getRiskLevel(score) {
        if (score >= 60) return { level: 'High', color: '#ff0000', icon: '🔴' };
        if (score >= 30) return { level: 'Medium', color: '#ff9900', icon: '🟠' };
        if (score >= 10) return { level: 'Low', color: '#ffff00', icon: '🟡' };
        return { level: 'Safe', color: '#00ff00', icon: '🟢' };
    }

    formatResult(url, findings, reputation, expanded) {
        const riskScore = this.calculateRiskScore(findings);
        const risk = this.getRiskLevel(riskScore);

        return `
            <div class="link-analyzer">
                <div class="analyzer-header">
                    <h2>🔍 Link Analyzer</h2>
                </div>

                <div class="url-display">
                    <span class="url-text">${url.original}</span>
                    <button onclick="linkAnalyzer.copyUrl('${url.original}')" title="Copy URL">📋</button>
                </div>

                <div class="risk-meter">
                    <div class="risk-score" style="border-color: ${risk.color}">
                        <span class="risk-icon">${risk.icon}</span>
                        <span class="risk-value">${riskScore}</span>
                        <span class="risk-label">${risk.level} Risk</span>
                    </div>
                </div>

                ${!url.valid ? `
                    <div class="analyzer-alert error">
                        <h3>❌ Invalid URL</h3>
                        <p>${url.error}</p>
                    </div>
                ` : ''}

                ${expanded?.expanded ? `
                    <div class="analyzer-section expanded-url">
                        <h3>🔗 URL Expansion</h3>
                        <div class="expansion-chain">
                            <span class="original">Original: ${expanded.chain[0]}</span>
                            <span class="arrow">↓</span>
                            <span class="destination">Destination: ${expanded.destination}</span>
                        </div>
                        <p class="warning">⚠️ This short URL redirects to a different destination!</p>
                    </div>
                ` : ''}

                <div class="analyzer-section">
                    <h3>📋 URL Breakdown</h3>
                    <div class="url-breakdown">
                        <div class="breakdown-item">
                            <span class="label">Protocol:</span>
                            <span class="value ${url.protocol === 'http:' ? 'warning' : ''}">${url.protocol || 'N/A'}</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="label">Domain:</span>
                            <span class="value">${url.domain || 'N/A'}</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="label">Subdomain:</span>
                            <span class="value">${url.subdomain || 'None'}</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="label">TLD:</span>
                            <span class="value">${url.tld || 'N/A'}</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="label">Path:</span>
                            <span class="value">${url.pathname || '/'}</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="label">Port:</span>
                            <span class="value">${url.port || 'Default'}</span>
                        </div>
                    </div>
                </div>

                ${Object.keys(url.params || {}).length > 0 ? `
                    <div class="analyzer-section">
                        <h3>📝 URL Parameters</h3>
                        <table class="params-table">
                            <thead><tr><th>Parameter</th><th>Value</th></tr></thead>
                            <tbody>
                                ${Object.entries(url.params).map(([k, v]) => `
                                    <tr>
                                        <td>${k}</td>
                                        <td class="param-value">${this.escapeHtml(v)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                ` : ''}

                ${findings.length > 0 ? `
                    <div class="analyzer-section">
                        <h3>⚠️ Security Findings</h3>
                        <div class="findings-list">
                            ${findings.map(f => `
                                <div class="finding ${f.severity}">
                                    <span class="finding-badge ${f.severity}">${f.severity.toUpperCase()}</span>
                                    <span class="finding-type">${f.type.replace('_', ' ')}</span>
                                    <p class="finding-message">${f.message}</p>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : `
                    <div class="analyzer-section">
                        <h3>✅ No Issues Found</h3>
                        <p>No obvious security issues detected in this URL.</p>
                    </div>
                `}

                <div class="analyzer-section">
                    <h3>🌐 Reputation Checks</h3>
                    <div class="reputation-list">
                        ${reputation.map(r => `
                            <div class="reputation-item ${r.safe === false ? 'unsafe' : r.safe === true ? 'safe' : ''}">
                                <span class="rep-service">${r.service}</span>
                                <span class="rep-status">${r.safe === true ? '✅' : r.safe === false ? '❌' : '❓'}</span>
                                <span class="rep-result">${r.result}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="analyzer-actions">
                    <button onclick="linkAnalyzer.openSafely('${url.original}')" class="action-btn">🔒 Open in Sandbox</button>
                    <button onclick="linkAnalyzer.checkVirusTotal('${url.domain}')" class="action-btn">🦠 Check VirusTotal</button>
                    <button onclick="linkAnalyzer.checkWhois('${url.domain}')" class="action-btn">📜 WHOIS Lookup</button>
                </div>
            </div>
        `;
    }

    escapeHtml(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    async analyzeLink(urlString) {
        marshall.ui.showPanel(`
            <div class="link-analyzer loading">
                <h2>🔍 Analyzing Link...</h2>
                <div class="loading-spinner"></div>
            </div>
        `, { title: 'Link Analyzer', width: 600, height: 650 });

        const url = this.parseUrl(urlString);
        const findings = url.valid ? this.checkPatterns(url) : [];
        const reputation = url.valid ? await this.checkReputation(url) : [];
        
        // Check for URL expansion if it's a shortener
        let expanded = null;
        if (findings.some(f => f.type === 'shortener')) {
            expanded = await this.expandShortUrl(url);
        }

        marshall.ui.updatePanel(this.formatResult(url, findings, reputation, expanded));
    }

    showAnalyzer() {
        marshall.ui.showPanel(`
            <div class="link-analyzer">
                <div class="analyzer-header">
                    <h2>🔍 Link Analyzer</h2>
                </div>
                <div class="manual-input">
                    <input type="text" id="url-input" placeholder="Enter URL to analyze..." class="url-input">
                    <button onclick="linkAnalyzer.analyzeInput()" class="analyze-btn">Analyze</button>
                </div>
                <p class="hint">Or right-click any link and select "Analyze Link"</p>
            </div>
        `, { title: 'Link Analyzer', width: 600, height: 400 });
    }

    analyzeInput() {
        const input = document.getElementById('url-input');
        if (input?.value) {
            this.analyzeLink(input.value);
        }
    }

    copyUrl(url) {
        marshall.clipboard.write(url);
        marshall.ui.notify('URL copied to clipboard', 'success');
    }

    openSafely(url) {
        // Open in isolated sandbox mode
        marshall.tabs.create({ url, sandbox: true });
    }

    checkVirusTotal(domain) {
        marshall.tabs.create({ url: `https://www.virustotal.com/gui/domain/${domain}` });
    }

    checkWhois(domain) {
        marshall.tabs.create({ url: `https://who.is/whois/${domain}` });
    }
}

const linkAnalyzer = new LinkAnalyzer();

marshall.extension.onActivate(async () => {
    await linkAnalyzer.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Link Analyzer] Extension deactivated');
});

marshall.extension.export('analyze', (url) => linkAnalyzer.analyzeLink(url));
