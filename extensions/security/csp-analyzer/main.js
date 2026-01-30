/**
 * CSP Analyzer Extension for Marshall Browser
 * Analyze Content Security Policy headers for vulnerabilities
 * Part of Marshall Extensions Collection
 */

class CSPAnalyzer {
    constructor() {
        this.directives = [
            'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
            'connect-src', 'media-src', 'object-src', 'frame-src', 'child-src',
            'worker-src', 'manifest-src', 'prefetch-src', 'navigate-to',
            'form-action', 'frame-ancestors', 'base-uri', 'sandbox',
            'report-uri', 'report-to', 'upgrade-insecure-requests', 'block-all-mixed-content'
        ];

        this.dangerousValues = {
            'unsafe-inline': { severity: 'high', message: 'Allows inline scripts/styles, enabling XSS attacks' },
            'unsafe-eval': { severity: 'critical', message: 'Allows eval(), extremely dangerous for XSS' },
            'unsafe-hashes': { severity: 'medium', message: 'Allows specific inline event handlers' },
            '*': { severity: 'critical', message: 'Allows loading from any source' },
            'data:': { severity: 'medium', message: 'Allows data: URIs which can embed scripts' },
            'blob:': { severity: 'low', message: 'Allows blob: URIs' }
        };

        this.recommendations = {
            'default-src': "Set to 'self' to restrict loading to same origin",
            'script-src': "Avoid 'unsafe-inline' and 'unsafe-eval', use nonces or hashes",
            'object-src': "Set to 'none' to prevent Flash/plugin attacks",
            'base-uri': "Set to 'self' or 'none' to prevent base tag hijacking",
            'frame-ancestors': "Set to prevent clickjacking attacks"
        };
    }

    async init() {
        marshall.keyboard.register('Ctrl+Shift+C', () => this.analyze());

        marshall.toolbar.register({
            id: 'csp-analyzer',
            title: 'CSP Analyzer',
            icon: '🛡️',
            onclick: () => this.analyze()
        });

        console.log('[CSP Analyzer] Extension initialized');
        return true;
    }

    parseCSP(cspHeader) {
        const policies = {};
        
        if (!cspHeader) return policies;

        const directives = cspHeader.split(';').map(d => d.trim()).filter(d => d);
        
        for (const directive of directives) {
            const parts = directive.split(/\s+/);
            const name = parts[0].toLowerCase();
            const values = parts.slice(1);
            policies[name] = values;
        }

        return policies;
    }

    analyzeDirective(name, values) {
        const findings = [];
        const effectiveValues = values || [];

        // Check for dangerous values
        for (const value of effectiveValues) {
            const normalizedValue = value.replace(/'/g, '').toLowerCase();
            
            for (const [dangerous, info] of Object.entries(this.dangerousValues)) {
                if (normalizedValue === dangerous || value === dangerous) {
                    findings.push({
                        directive: name,
                        value: value,
                        severity: info.severity,
                        message: info.message,
                        type: 'dangerous_value'
                    });
                }
            }

            // Check for overly permissive hosts
            if (value.includes('*') && value !== '*') {
                findings.push({
                    directive: name,
                    value: value,
                    severity: 'medium',
                    message: `Wildcard in host (${value}) may be overly permissive`,
                    type: 'wildcard_host'
                });
            }

            // Check for HTTP sources
            if (value.startsWith('http:')) {
                findings.push({
                    directive: name,
                    value: value,
                    severity: 'medium',
                    message: 'HTTP source allows mixed content attacks',
                    type: 'insecure_source'
                });
            }
        }

        return findings;
    }

    getMissingDirectives(policies) {
        const critical = ['default-src', 'script-src', 'object-src', 'base-uri'];
        const missing = [];

        for (const directive of critical) {
            if (!policies[directive] && directive !== 'default-src') {
                // Check if covered by default-src
                if (!policies['default-src']) {
                    missing.push({
                        directive: directive,
                        severity: directive === 'object-src' ? 'high' : 'medium',
                        message: `Missing ${directive} directive`,
                        recommendation: this.recommendations[directive]
                    });
                }
            }
        }

        if (!policies['frame-ancestors']) {
            missing.push({
                directive: 'frame-ancestors',
                severity: 'medium',
                message: 'Missing frame-ancestors (clickjacking protection)',
                recommendation: this.recommendations['frame-ancestors']
            });
        }

        return missing;
    }

    calculateScore(findings, missing, hasCSP) {
        if (!hasCSP) return 0;

        let score = 100;

        for (const finding of findings) {
            switch (finding.severity) {
                case 'critical': score -= 25; break;
                case 'high': score -= 15; break;
                case 'medium': score -= 10; break;
                case 'low': score -= 5; break;
            }
        }

        for (const m of missing) {
            switch (m.severity) {
                case 'high': score -= 15; break;
                case 'medium': score -= 10; break;
            }
        }

        return Math.max(0, score);
    }

    getScoreColor(score) {
        if (score >= 80) return '#00ff00';
        if (score >= 60) return '#ffff00';
        if (score >= 40) return '#ff9900';
        return '#ff0000';
    }

    getScoreLabel(score) {
        if (score >= 80) return 'Good';
        if (score >= 60) return 'Fair';
        if (score >= 40) return 'Weak';
        return 'Poor';
    }

    getSeverityIcon(severity) {
        switch (severity) {
            case 'critical': return '🔴';
            case 'high': return '🟠';
            case 'medium': return '🟡';
            case 'low': return '🟢';
            default: return '⚪';
        }
    }

    generateRecommendedCSP(currentPolicies) {
        const recommended = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'"],
            'img-src': ["'self'", 'data:', 'https:'],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
            'frame-ancestors': ["'self'"],
            'form-action': ["'self'"],
            'upgrade-insecure-requests': []
        };

        return Object.entries(recommended)
            .map(([dir, vals]) => vals.length ? `${dir} ${vals.join(' ')}` : dir)
            .join('; ');
    }

    formatResult(url, cspHeader, reportOnlyHeader) {
        const hasCSP = !!cspHeader;
        const hasReportOnly = !!reportOnlyHeader;
        const policies = this.parseCSP(cspHeader);
        const reportOnlyPolicies = this.parseCSP(reportOnlyHeader);

        let allFindings = [];
        
        // Analyze each directive
        for (const [name, values] of Object.entries(policies)) {
            const findings = this.analyzeDirective(name, values);
            allFindings = allFindings.concat(findings);
        }

        const missingDirectives = this.getMissingDirectives(policies);
        const score = this.calculateScore(allFindings, missingDirectives, hasCSP);

        const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
        const highCount = allFindings.filter(f => f.severity === 'high').length;
        const mediumCount = allFindings.filter(f => f.severity === 'medium').length;

        return `
            <div class="csp-analyzer">
                <div class="csp-header">
                    <h2>🛡️ CSP Analyzer</h2>
                    <span class="csp-url">${url}</span>
                </div>

                <div class="csp-score-container">
                    <div class="csp-score" style="border-color: ${this.getScoreColor(score)}">
                        <span class="score-value">${score}</span>
                        <span class="score-label">${this.getScoreLabel(score)}</span>
                    </div>
                    <div class="csp-summary">
                        <div class="summary-item ${!hasCSP ? 'missing' : ''}">
                            ${hasCSP ? '✅' : '❌'} Content-Security-Policy
                        </div>
                        <div class="summary-item">
                            ${hasReportOnly ? '✅' : '⚪'} CSP Report-Only
                        </div>
                        <div class="summary-item">
                            📊 ${Object.keys(policies).length} directives found
                        </div>
                    </div>
                </div>

                ${!hasCSP ? `
                    <div class="csp-alert critical">
                        <h3>⚠️ No CSP Header Detected</h3>
                        <p>This site has no Content Security Policy, leaving it vulnerable to XSS and injection attacks.</p>
                    </div>
                ` : ''}

                ${allFindings.length > 0 ? `
                    <div class="csp-section">
                        <h3>🔍 Security Findings</h3>
                        <div class="findings-summary">
                            ${criticalCount > 0 ? `<span class="badge critical">🔴 ${criticalCount} Critical</span>` : ''}
                            ${highCount > 0 ? `<span class="badge high">🟠 ${highCount} High</span>` : ''}
                            ${mediumCount > 0 ? `<span class="badge medium">🟡 ${mediumCount} Medium</span>` : ''}
                        </div>
                        <div class="findings-list">
                            ${allFindings.map(f => `
                                <div class="finding ${f.severity}">
                                    <span class="finding-icon">${this.getSeverityIcon(f.severity)}</span>
                                    <div class="finding-content">
                                        <strong>${f.directive}</strong>: <code>${f.value}</code>
                                        <p>${f.message}</p>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}

                ${missingDirectives.length > 0 ? `
                    <div class="csp-section">
                        <h3>📋 Missing Directives</h3>
                        <div class="missing-list">
                            ${missingDirectives.map(m => `
                                <div class="missing-item ${m.severity}">
                                    <span class="finding-icon">${this.getSeverityIcon(m.severity)}</span>
                                    <div class="missing-content">
                                        <strong>${m.directive}</strong>
                                        <p>${m.message}</p>
                                        <p class="recommendation">💡 ${m.recommendation}</p>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}

                <div class="csp-section">
                    <h3>📜 Current Policy</h3>
                    <pre class="csp-raw">${cspHeader || 'No CSP header present'}</pre>
                </div>

                <div class="csp-section">
                    <h3>✨ Recommended Policy</h3>
                    <pre class="csp-recommended">${this.generateRecommendedCSP(policies)}</pre>
                    <button onclick="cspAnalyzer.copyRecommended()" class="csp-copy-btn">📋 Copy Recommended CSP</button>
                </div>

                <div class="csp-section">
                    <h3>📖 Directive Reference</h3>
                    <div class="directive-grid">
                        ${Object.entries(policies).map(([name, values]) => `
                            <div class="directive-item">
                                <strong>${name}</strong>
                                <span>${values.join(' ')}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    async analyze() {
        const tab = await marshall.tabs.getCurrent();
        const headers = await marshall.network.getResponseHeaders(tab.url);
        
        const cspHeader = headers['content-security-policy'] || headers['Content-Security-Policy'];
        const reportOnlyHeader = headers['content-security-policy-report-only'];

        marshall.ui.showPanel(this.formatResult(tab.url, cspHeader, reportOnlyHeader), {
            title: 'CSP Analyzer',
            width: 700,
            height: 600
        });
    }

    async copyRecommended() {
        const el = document.querySelector('.csp-recommended');
        await marshall.clipboard.write(el.textContent);
        marshall.ui.notify('Recommended CSP copied to clipboard', 'success');
    }
}

const cspAnalyzer = new CSPAnalyzer();

marshall.extension.onActivate(async () => {
    await cspAnalyzer.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[CSP Analyzer] Extension deactivated');
});

marshall.extension.export('parse', (csp) => cspAnalyzer.parseCSP(csp));
marshall.extension.export('analyze', (csp) => cspAnalyzer.analyzeDirective(csp));
