/**
 * Cookie Manager Extension for Marshall Browser
 * Advanced cookie analysis and management
 * Part of Marshall Extensions Collection
 */

class CookieManager {
    constructor() {
        this.knownTrackers = new Set([
            'doubleclick.net', 'facebook.com', 'google-analytics.com',
            'googlesyndication.com', 'googleadservices.com', 'analytics.google.com',
            'fbcdn.net', 'scorecardresearch.com', 'quantserve.com',
            'adsrvr.org', 'criteo.com', 'pubmatic.com', 'rubiconproject.com',
            'adnxs.com', 'taboola.com', 'outbrain.com', 'amazon-adsystem.com'
        ]);
        this.cookieRisks = new Map();
    }

    async init() {
        // Register toolbar button
        marshall.toolbar.addButton({
            id: 'cookie-manager-btn',
            icon: '🍪',
            tooltip: 'Cookie Manager',
            onclick: () => this.showManager()
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+K', () => this.showManager());

        // Register context menu
        marshall.contextMenu.register({
            id: 'cookie-manager',
            title: 'Manage Cookies',
            contexts: ['page'],
            onclick: () => this.showManager()
        });

        // Auto-analyze on page load
        const autoAnalyze = await marshall.storage.get('cookie_auto_analyze');
        if (autoAnalyze !== false) {
            marshall.tabs.onNavigate((tab) => this.updateBadge(tab));
        }

        console.log('[Cookie Manager] Extension initialized');
        return true;
    }

    async getCookies(domain = null) {
        if (domain) {
            return await marshall.cookies.getAll({ domain });
        }
        const tab = await marshall.tabs.getCurrent();
        const url = new URL(tab.url);
        return await marshall.cookies.getAll({ domain: url.hostname });
    }

    async getAllCookies() {
        return await marshall.cookies.getAll({});
    }

    analyzeCookie(cookie) {
        const risks = [];
        const domain = cookie.domain.replace(/^\./, '');

        // Check if it's a tracker
        if (this.isTracker(domain)) {
            risks.push({ type: 'tracker', severity: 'high', message: 'Known tracking cookie' });
        }

        // Check for third-party
        if (cookie.domain.startsWith('.')) {
            risks.push({ type: 'third-party', severity: 'medium', message: 'Third-party cookie' });
        }

        // Check expiration
        if (cookie.expirationDate) {
            const daysUntilExpire = (cookie.expirationDate - Date.now() / 1000) / 86400;
            if (daysUntilExpire > 365) {
                risks.push({ type: 'persistent', severity: 'medium', message: `Expires in ${Math.round(daysUntilExpire)} days` });
            }
        } else {
            risks.push({ type: 'session', severity: 'low', message: 'Session cookie' });
        }

        // Check HttpOnly flag
        if (!cookie.httpOnly) {
            risks.push({ type: 'script-accessible', severity: 'low', message: 'Accessible to JavaScript' });
        }

        // Check Secure flag
        if (!cookie.secure) {
            risks.push({ type: 'insecure', severity: 'medium', message: 'Not secure (HTTP)' });
        }

        // Check SameSite
        if (!cookie.sameSite || cookie.sameSite === 'none') {
            risks.push({ type: 'cross-site', severity: 'medium', message: 'Cross-site requests allowed' });
        }

        // Check for suspicious names
        const suspiciousPatterns = ['_ga', '_gid', '_fbp', 'visitor', 'track', 'uid', 'sess'];
        if (suspiciousPatterns.some(p => cookie.name.toLowerCase().includes(p))) {
            risks.push({ type: 'suspicious-name', severity: 'low', message: 'Potentially tracking identifier' });
        }

        return {
            cookie,
            risks,
            riskScore: risks.reduce((sum, r) => sum + (r.severity === 'high' ? 3 : r.severity === 'medium' ? 2 : 1), 0),
            isTracker: this.isTracker(domain)
        };
    }

    isTracker(domain) {
        return Array.from(this.knownTrackers).some(tracker => 
            domain === tracker || domain.endsWith('.' + tracker)
        );
    }

    categorize(cookies) {
        const categories = {
            essential: [],
            functional: [],
            analytics: [],
            advertising: [],
            unknown: []
        };

        const essentialPatterns = ['session', 'csrf', 'auth', 'login', 'token'];
        const analyticsPatterns = ['_ga', '_gid', 'analytics', 'stat'];
        const advertisingPatterns = ['_fbp', 'ad', 'track', 'pixel', 'campaign'];

        cookies.forEach(cookie => {
            const name = cookie.name.toLowerCase();
            const analysis = this.analyzeCookie(cookie);

            if (analysis.isTracker) {
                categories.advertising.push(analysis);
            } else if (essentialPatterns.some(p => name.includes(p))) {
                categories.essential.push(analysis);
            } else if (analyticsPatterns.some(p => name.includes(p))) {
                categories.analytics.push(analysis);
            } else if (advertisingPatterns.some(p => name.includes(p))) {
                categories.advertising.push(analysis);
            } else {
                categories.unknown.push(analysis);
            }
        });

        return categories;
    }

    formatCookieValue(value, maxLength = 50) {
        if (!value) return '<empty>';
        if (value.length > maxLength) {
            return value.substring(0, maxLength) + '...';
        }
        return value;
    }

    formatExpiration(expirationDate) {
        if (!expirationDate) return 'Session';
        const date = new Date(expirationDate * 1000);
        const now = new Date();
        const diff = date - now;
        
        if (diff < 0) return 'Expired';
        if (diff < 86400000) return 'Today';
        if (diff < 604800000) return `${Math.ceil(diff / 86400000)} days`;
        if (diff < 2592000000) return `${Math.ceil(diff / 604800000)} weeks`;
        if (diff < 31536000000) return `${Math.ceil(diff / 2592000000)} months`;
        return `${Math.ceil(diff / 31536000000)} years`;
    }

    getRiskBadge(riskScore) {
        if (riskScore >= 5) return '<span class="risk-badge high">High Risk</span>';
        if (riskScore >= 3) return '<span class="risk-badge medium">Medium</span>';
        if (riskScore >= 1) return '<span class="risk-badge low">Low</span>';
        return '<span class="risk-badge safe">Safe</span>';
    }

    formatResult(cookies, categories, domain) {
        const totalRisk = cookies.reduce((sum, c) => sum + this.analyzeCookie(c).riskScore, 0);
        const trackerCount = cookies.filter(c => this.isTracker(c.domain.replace(/^\./, ''))).length;

        return `
            <div class="cookie-manager">
                <div class="cookie-header">
                    <h2>🍪 Cookie Manager</h2>
                    <span class="cookie-domain">${domain}</span>
                </div>

                <div class="cookie-stats">
                    <div class="stat-box">
                        <span class="stat-number">${cookies.length}</span>
                        <span class="stat-label">Total Cookies</span>
                    </div>
                    <div class="stat-box ${trackerCount > 0 ? 'warning' : ''}">
                        <span class="stat-number">${trackerCount}</span>
                        <span class="stat-label">Trackers</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-number">${Math.round(totalRisk / cookies.length * 10) / 10 || 0}</span>
                        <span class="stat-label">Avg Risk</span>
                    </div>
                </div>

                <div class="cookie-actions">
                    <button onclick="cookieManager.deleteAll('${domain}')" class="action-btn danger">
                        🗑️ Delete All
                    </button>
                    <button onclick="cookieManager.deleteTrackers()" class="action-btn warning">
                        🚫 Delete Trackers
                    </button>
                    <button onclick="cookieManager.exportCookies()" class="action-btn">
                        📥 Export
                    </button>
                </div>

                <div class="cookie-categories">
                    ${Object.entries(categories).map(([cat, items]) => items.length > 0 ? `
                        <div class="category-section">
                            <div class="category-header" onclick="this.parentElement.classList.toggle('expanded')">
                                <span class="category-icon">${this.getCategoryIcon(cat)}</span>
                                <span class="category-name">${cat.charAt(0).toUpperCase() + cat.slice(1)}</span>
                                <span class="category-count">${items.length}</span>
                            </div>
                            <div class="category-cookies">
                                ${items.map(analysis => `
                                    <div class="cookie-item ${analysis.isTracker ? 'tracker' : ''}">
                                        <div class="cookie-info">
                                            <span class="cookie-name">${analysis.cookie.name}</span>
                                            ${this.getRiskBadge(analysis.riskScore)}
                                        </div>
                                        <div class="cookie-details">
                                            <span class="cookie-domain">${analysis.cookie.domain}</span>
                                            <span class="cookie-expires">${this.formatExpiration(analysis.cookie.expirationDate)}</span>
                                        </div>
                                        <div class="cookie-value">${this.formatCookieValue(analysis.cookie.value)}</div>
                                        <div class="cookie-flags">
                                            ${analysis.cookie.secure ? '<span class="flag secure">Secure</span>' : '<span class="flag insecure">Insecure</span>'}
                                            ${analysis.cookie.httpOnly ? '<span class="flag http-only">HttpOnly</span>' : ''}
                                            ${analysis.cookie.sameSite ? `<span class="flag samesite">${analysis.cookie.sameSite}</span>` : ''}
                                        </div>
                                        <div class="cookie-actions-inline">
                                            <button onclick="cookieManager.editCookie('${analysis.cookie.name}', '${analysis.cookie.domain}')" title="Edit">✏️</button>
                                            <button onclick="cookieManager.deleteCookie('${analysis.cookie.name}', '${analysis.cookie.domain}')" title="Delete">🗑️</button>
                                            <button onclick="cookieManager.copyCookie('${analysis.cookie.name}')" title="Copy">📋</button>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : '').join('')}
                </div>
            </div>
        `;
    }

    getCategoryIcon(category) {
        const icons = {
            essential: '🔐',
            functional: '⚙️',
            analytics: '📊',
            advertising: '📢',
            unknown: '❓'
        };
        return icons[category] || '🍪';
    }

    async showManager() {
        const tab = await marshall.tabs.getCurrent();
        const url = new URL(tab.url);
        const domain = url.hostname;

        marshall.ui.showPanel('<div class="cookie-loading">🍪 Loading cookies...</div>');

        const cookies = await this.getCookies();
        const categories = this.categorize(cookies);

        marshall.ui.showPanel(this.formatResult(cookies, categories, domain), {
            title: 'Cookie Manager',
            width: 600,
            height: 700
        });
    }

    async updateBadge(tab) {
        if (tab.url.startsWith('marshall://') || tab.url.startsWith('file://')) {
            marshall.toolbar.updateButton('cookie-manager-btn', { badge: '' });
            return;
        }

        const url = new URL(tab.url);
        const cookies = await this.getCookies(url.hostname);
        const trackerCount = cookies.filter(c => this.isTracker(c.domain.replace(/^\./, ''))).length;

        const showBadge = await marshall.storage.get('cookie_show_badge');
        if (showBadge !== false) {
            marshall.toolbar.updateButton('cookie-manager-btn', {
                badge: cookies.length.toString(),
                badgeColor: trackerCount > 0 ? '#f44336' : '#4CAF50'
            });
        }
    }

    async deleteCookie(name, domain) {
        await marshall.cookies.remove({ name, domain });
        marshall.ui.notify(`Deleted cookie: ${name}`, 'success');
        this.showManager(); // Refresh
    }

    async deleteAll(domain) {
        const cookies = await this.getCookies(domain);
        for (const cookie of cookies) {
            await marshall.cookies.remove({ name: cookie.name, domain: cookie.domain });
        }
        marshall.ui.notify(`Deleted ${cookies.length} cookies`, 'success');
        this.showManager();
    }

    async deleteTrackers() {
        const allCookies = await this.getAllCookies();
        let deleted = 0;
        for (const cookie of allCookies) {
            if (this.isTracker(cookie.domain.replace(/^\./, ''))) {
                await marshall.cookies.remove({ name: cookie.name, domain: cookie.domain });
                deleted++;
            }
        }
        marshall.ui.notify(`Deleted ${deleted} tracking cookies`, 'success');
        this.showManager();
    }

    async exportCookies() {
        const cookies = await this.getCookies();
        const data = JSON.stringify(cookies, null, 2);
        marshall.download.save(data, 'cookies.json', 'application/json');
        marshall.ui.notify('Cookies exported', 'success');
    }

    async copyCookie(name) {
        const cookies = await this.getCookies();
        const cookie = cookies.find(c => c.name === name);
        if (cookie) {
            await marshall.clipboard.write(JSON.stringify(cookie, null, 2));
            marshall.ui.notify('Cookie copied to clipboard', 'success');
        }
    }
}

// Extension entry point
const cookieManager = new CookieManager();

marshall.extension.onActivate(async () => {
    await cookieManager.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Cookie Manager] Extension deactivated');
});

marshall.extension.export('getCookies', () => cookieManager.getCookies());
marshall.extension.export('analyze', (cookie) => cookieManager.analyzeCookie(cookie));
