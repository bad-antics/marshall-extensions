/**
 * Subdomain Finder Extension for Marshall Browser
 * Passive subdomain enumeration using public sources
 * Part of Marshall Extensions Collection
 */

class SubdomainFinder {
    constructor() {
        this.sources = {
            crtsh: {
                name: 'crt.sh',
                url: 'https://crt.sh/?q=%25.{domain}&output=json',
                parse: this.parseCrtSh.bind(this)
            },
            hackertarget: {
                name: 'HackerTarget',
                url: 'https://api.hackertarget.com/hostsearch/?q={domain}',
                parse: this.parseHackerTarget.bind(this)
            },
            alienvault: {
                name: 'AlienVault OTX',
                url: 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                parse: this.parseAlienVault.bind(this)
            },
            threatcrowd: {
                name: 'ThreatCrowd',
                url: 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                parse: this.parseThreatCrowd.bind(this)
            },
            urlscan: {
                name: 'URLScan.io',
                url: 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                parse: this.parseUrlScan.bind(this)
            }
        };
    }

    async init() {
        marshall.keyboard.register('Ctrl+Shift+S', () => this.showFinder());

        marshall.toolbar.register({
            id: 'subdomain-finder',
            title: 'Subdomain Finder',
            icon: '🔍',
            onclick: () => this.showFinder()
        });

        marshall.contextMenu.register({
            id: 'find-subdomains',
            title: 'Find Subdomains',
            contexts: ['selection', 'page'],
            onclick: (info) => this.findForSelection(info)
        });

        console.log('[Subdomain Finder] Extension initialized');
        return true;
    }

    extractDomain(url) {
        try {
            const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
            const parts = parsed.hostname.split('.');
            // Get root domain (last 2 parts, or 3 for co.uk style)
            if (parts.length >= 2) {
                return parts.slice(-2).join('.');
            }
            return parsed.hostname;
        } catch (e) {
            return url;
        }
    }

    parseCrtSh(data) {
        try {
            const json = JSON.parse(data);
            const domains = new Set();
            for (const entry of json) {
                const names = entry.name_value.split('\n');
                for (const name of names) {
                    const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                    if (clean) domains.add(clean);
                }
            }
            return Array.from(domains);
        } catch (e) {
            return [];
        }
    }

    parseHackerTarget(data) {
        try {
            if (data.includes('error')) return [];
            const lines = data.split('\n').filter(l => l.trim());
            return lines.map(l => l.split(',')[0].trim());
        } catch (e) {
            return [];
        }
    }

    parseAlienVault(data) {
        try {
            const json = JSON.parse(data);
            const domains = new Set();
            for (const entry of json.passive_dns || []) {
                if (entry.hostname) {
                    domains.add(entry.hostname.toLowerCase());
                }
            }
            return Array.from(domains);
        } catch (e) {
            return [];
        }
    }

    parseThreatCrowd(data) {
        try {
            const json = JSON.parse(data);
            return json.subdomains || [];
        } catch (e) {
            return [];
        }
    }

    parseUrlScan(data) {
        try {
            const json = JSON.parse(data);
            const domains = new Set();
            for (const result of json.results || []) {
                if (result.page?.domain) {
                    domains.add(result.page.domain.toLowerCase());
                }
            }
            return Array.from(domains);
        } catch (e) {
            return [];
        }
    }

    async querySource(sourceName, domain) {
        const source = this.sources[sourceName];
        if (!source) return { name: sourceName, subdomains: [], error: 'Unknown source' };

        try {
            const url = source.url.replace('{domain}', encodeURIComponent(domain));
            const response = await marshall.network.fetch(url, {
                timeout: 15000,
                headers: {
                    'User-Agent': 'Marshall Browser/1.0'
                }
            });

            if (!response.ok) {
                return { name: source.name, subdomains: [], error: `HTTP ${response.status}` };
            }

            const data = await response.text();
            const subdomains = source.parse(data);

            return {
                name: source.name,
                subdomains: subdomains,
                count: subdomains.length
            };
        } catch (e) {
            return { name: source.name, subdomains: [], error: e.message };
        }
    }

    async findSubdomains(domain, enabledSources = null) {
        const rootDomain = this.extractDomain(domain);
        const sources = enabledSources || Object.keys(this.sources);
        
        const results = await Promise.allSettled(
            sources.map(s => this.querySource(s, rootDomain))
        );

        const sourceResults = results.map((r, i) => 
            r.status === 'fulfilled' ? r.value : { name: sources[i], subdomains: [], error: r.reason }
        );

        // Merge and deduplicate all subdomains
        const allSubdomains = new Set();
        const subdomainSources = {};

        for (const result of sourceResults) {
            for (const subdomain of result.subdomains || []) {
                const normalized = subdomain.toLowerCase();
                if (normalized.endsWith(rootDomain) || normalized === rootDomain) {
                    allSubdomains.add(normalized);
                    if (!subdomainSources[normalized]) {
                        subdomainSources[normalized] = [];
                    }
                    subdomainSources[normalized].push(result.name);
                }
            }
        }

        return {
            domain: rootDomain,
            sources: sourceResults,
            subdomains: Array.from(allSubdomains).sort(),
            subdomainSources: subdomainSources,
            total: allSubdomains.size
        };
    }

    categorizeSubdomains(subdomains) {
        const categories = {
            'Web': [],
            'API': [],
            'Mail': [],
            'Admin': [],
            'Development': [],
            'CDN': [],
            'Other': []
        };

        const patterns = {
            'Web': /^(www|web|portal|site)/,
            'API': /^(api|rest|graphql|ws|socket)/,
            'Mail': /^(mail|smtp|imap|pop|mx|email)/,
            'Admin': /^(admin|panel|dashboard|cms|manage|control)/,
            'Development': /^(dev|test|staging|qa|beta|uat|sandbox|demo)/,
            'CDN': /^(cdn|static|assets|media|img|images|files)/
        };

        for (const subdomain of subdomains) {
            let categorized = false;
            for (const [category, pattern] of Object.entries(patterns)) {
                if (pattern.test(subdomain)) {
                    categories[category].push(subdomain);
                    categorized = true;
                    break;
                }
            }
            if (!categorized) {
                categories['Other'].push(subdomain);
            }
        }

        return categories;
    }

    formatResult(result) {
        const categories = this.categorizeSubdomains(result.subdomains);
        const successSources = result.sources.filter(s => !s.error);
        const failedSources = result.sources.filter(s => s.error);

        return `
            <div class="subdomain-finder">
                <div class="finder-header">
                    <h2>🔍 Subdomain Finder</h2>
                    <span class="domain-badge">${result.domain}</span>
                </div>

                <div class="finder-stats">
                    <div class="stat-card">
                        <span class="stat-value">${result.total}</span>
                        <span class="stat-label">Subdomains Found</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value">${successSources.length}/${result.sources.length}</span>
                        <span class="stat-label">Sources Queried</span>
                    </div>
                </div>

                <div class="finder-section">
                    <h3>📡 Data Sources</h3>
                    <div class="sources-grid">
                        ${result.sources.map(s => `
                            <div class="source-item ${s.error ? 'error' : 'success'}">
                                <span class="source-icon">${s.error ? '❌' : '✅'}</span>
                                <span class="source-name">${s.name}</span>
                                <span class="source-count">${s.error ? s.error : `${s.count} found`}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="finder-section">
                    <h3>📂 Subdomains by Category</h3>
                    <div class="category-grid">
                        ${Object.entries(categories).filter(([_, subs]) => subs.length > 0).map(([cat, subs]) => `
                            <div class="category-card">
                                <h4>${cat} <span class="count">(${subs.length})</span></h4>
                                <ul class="subdomain-list">
                                    ${subs.slice(0, 10).map(s => `
                                        <li>
                                            <a href="https://${s}" target="_blank" class="subdomain-link">${s}</a>
                                            <span class="source-hint">${(result.subdomainSources[s] || []).join(', ')}</span>
                                        </li>
                                    `).join('')}
                                    ${subs.length > 10 ? `<li class="more">...and ${subs.length - 10} more</li>` : ''}
                                </ul>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="finder-section">
                    <h3>📋 All Subdomains (${result.total})</h3>
                    <div class="finder-toolbar">
                        <input type="text" id="subdomain-search" placeholder="🔍 Filter..." oninput="subdomainFinder.filterList(this.value)">
                        <button onclick="subdomainFinder.copyAll()">📋 Copy All</button>
                        <button onclick="subdomainFinder.exportCSV()">💾 Export CSV</button>
                        <button onclick="subdomainFinder.exportJson()">📄 Export JSON</button>
                    </div>
                    <div class="subdomain-full-list" id="subdomain-full-list">
                        ${result.subdomains.map(s => `
                            <div class="subdomain-item" data-domain="${s}">
                                <a href="https://${s}" target="_blank">${s}</a>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    filterList(query) {
        const items = document.querySelectorAll('.subdomain-item');
        const q = query.toLowerCase();
        items.forEach(item => {
            const domain = item.dataset.domain;
            item.style.display = domain.includes(q) ? 'block' : 'none';
        });
    }

    async copyAll() {
        const items = document.querySelectorAll('.subdomain-item');
        const domains = Array.from(items).map(i => i.dataset.domain).join('\n');
        await marshall.clipboard.write(domains);
        marshall.ui.notify(`Copied ${items.length} subdomains to clipboard`, 'success');
    }

    exportCSV() {
        const items = document.querySelectorAll('.subdomain-item');
        const csv = 'subdomain\n' + Array.from(items).map(i => i.dataset.domain).join('\n');
        marshall.download.save(csv, 'subdomains.csv', 'text/csv');
    }

    exportJson() {
        const items = document.querySelectorAll('.subdomain-item');
        const data = { subdomains: Array.from(items).map(i => i.dataset.domain) };
        marshall.download.save(JSON.stringify(data, null, 2), 'subdomains.json', 'application/json');
    }

    async showFinder() {
        const tab = await marshall.tabs.getCurrent();
        const domain = this.extractDomain(tab.url);

        marshall.ui.showPanel(`
            <div class="subdomain-finder loading">
                <h2>🔍 Finding Subdomains...</h2>
                <p>Querying ${Object.keys(this.sources).length} sources for <strong>${domain}</strong></p>
                <div class="progress-bar"><div class="progress-fill"></div></div>
            </div>
        `, { title: 'Subdomain Finder', width: 700, height: 600 });

        const result = await this.findSubdomains(domain);
        marshall.ui.updatePanel(this.formatResult(result));
    }

    async findForSelection(info) {
        const domain = info.selectionText || this.extractDomain(info.pageUrl);
        
        marshall.ui.showPanel(`
            <div class="subdomain-finder loading">
                <h2>🔍 Finding Subdomains...</h2>
                <p>Querying sources for <strong>${domain}</strong></p>
            </div>
        `, { title: 'Subdomain Finder', width: 700, height: 600 });

        const result = await this.findSubdomains(domain);
        marshall.ui.updatePanel(this.formatResult(result));
    }
}

const subdomainFinder = new SubdomainFinder();

marshall.extension.onActivate(async () => {
    await subdomainFinder.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Subdomain Finder] Extension deactivated');
});

marshall.extension.export('find', (domain) => subdomainFinder.findSubdomains(domain));
