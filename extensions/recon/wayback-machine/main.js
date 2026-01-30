/**
 * Wayback Machine Extension for Marshall Browser
 * Query archive.org for historical snapshots
 * Part of Marshall Extensions Collection
 */

class WaybackMachine {
    constructor() {
        this.baseUrl = 'https://archive.org/wayback/available';
        this.cdxUrl = 'https://web.archive.org/cdx/search/cdx';
        this.cache = new Map();
    }

    async init() {
        // Register context menu
        marshall.contextMenu.register({
            id: 'wayback-lookup',
            title: 'Check Wayback Machine',
            contexts: ['page', 'link'],
            onclick: (info) => this.contextMenuHandler(info)
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+A', () => this.checkCurrentPage());

        // Register toolbar button
        marshall.toolbar.addButton({
            id: 'wayback-btn',
            icon: '📜',
            tooltip: 'Check Wayback Machine',
            onclick: () => this.checkCurrentPage()
        });

        // Auto-check on page load if enabled
        const autoCheck = await marshall.storage.get('wayback_auto_check');
        if (autoCheck) {
            marshall.tabs.onNavigate((tab) => this.autoCheckHandler(tab));
        }

        console.log('[Wayback Machine] Extension initialized');
        return true;
    }

    async getSnapshots(url, limit = 100) {
        try {
            const params = new URLSearchParams({
                url: url,
                output: 'json',
                limit: limit,
                fl: 'timestamp,original,statuscode,mimetype,length'
            });

            const response = await marshall.network.fetch(
                `${this.cdxUrl}?${params.toString()}`
            );

            if (!response.ok) {
                throw new Error(`CDX API error: ${response.status}`);
            }

            const text = await response.text();
            const lines = text.trim().split('\n');
            
            if (lines.length <= 1) {
                return [];
            }

            // Parse CDX response (skip header)
            return lines.slice(1).map(line => {
                const parts = line.split(' ');
                return {
                    timestamp: parts[0],
                    url: parts[1],
                    statusCode: parts[2],
                    mimeType: parts[3],
                    size: parts[4],
                    archiveUrl: `https://web.archive.org/web/${parts[0]}/${parts[1]}`
                };
            });
        } catch (error) {
            console.error('[Wayback Machine] Error fetching snapshots:', error);
            return [];
        }
    }

    async getClosestSnapshot(url, timestamp = null) {
        try {
            let apiUrl = `${this.baseUrl}?url=${encodeURIComponent(url)}`;
            if (timestamp) {
                apiUrl += `&timestamp=${timestamp}`;
            }

            const response = await marshall.network.fetch(apiUrl);
            
            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();
            return data.archived_snapshots?.closest || null;
        } catch (error) {
            console.error('[Wayback Machine] Error:', error);
            return null;
        }
    }

    formatTimestamp(ts) {
        if (!ts || ts.length < 14) return 'Unknown';
        const year = ts.substring(0, 4);
        const month = ts.substring(4, 6);
        const day = ts.substring(6, 8);
        const hour = ts.substring(8, 10);
        const min = ts.substring(10, 12);
        return `${year}-${month}-${day} ${hour}:${min}`;
    }

    formatSize(bytes) {
        if (!bytes) return 'N/A';
        const num = parseInt(bytes);
        if (num < 1024) return `${num} B`;
        if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
        return `${(num / (1024 * 1024)).toFixed(1)} MB`;
    }

    groupByYear(snapshots) {
        const groups = {};
        snapshots.forEach(snap => {
            const year = snap.timestamp.substring(0, 4);
            if (!groups[year]) groups[year] = [];
            groups[year].push(snap);
        });
        return groups;
    }

    formatResult(url, snapshots, closest) {
        if (snapshots.length === 0 && !closest) {
            return `
                <div class="wayback-result">
                    <div class="wayback-header">
                        <h2>📜 Wayback Machine</h2>
                        <span class="wayback-url">${url}</span>
                    </div>
                    <div class="wayback-empty">
                        <p>❌ No archived snapshots found for this URL</p>
                        <a href="https://web.archive.org/save/${url}" target="_blank" class="wayback-save-btn">
                            💾 Save this page to Archive.org
                        </a>
                    </div>
                </div>
            `;
        }

        const grouped = this.groupByYear(snapshots);
        const years = Object.keys(grouped).sort().reverse();

        return `
            <div class="wayback-result">
                <div class="wayback-header">
                    <h2>📜 Wayback Machine</h2>
                    <span class="wayback-url">${url}</span>
                </div>

                <div class="wayback-stats">
                    <div class="stat-box">
                        <span class="stat-number">${snapshots.length}</span>
                        <span class="stat-label">Snapshots</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-number">${years.length}</span>
                        <span class="stat-label">Years</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-number">${snapshots.length > 0 ? this.formatTimestamp(snapshots[0].timestamp).split(' ')[0] : 'N/A'}</span>
                        <span class="stat-label">First Archive</span>
                    </div>
                </div>

                ${closest ? `
                <div class="wayback-closest">
                    <h3>🎯 Closest Snapshot</h3>
                    <a href="${closest.url}" target="_blank">${this.formatTimestamp(closest.timestamp)}</a>
                    <span class="status-badge status-${closest.status}">${closest.status}</span>
                </div>
                ` : ''}

                <div class="wayback-timeline">
                    <h3>📅 Timeline</h3>
                    ${years.map(year => `
                        <div class="year-group">
                            <div class="year-header" onclick="this.parentElement.classList.toggle('expanded')">
                                <span class="year-label">${year}</span>
                                <span class="snapshot-count">${grouped[year].length} snapshots</span>
                            </div>
                            <div class="year-snapshots">
                                ${grouped[year].slice(0, 20).map(snap => `
                                    <a href="${snap.archiveUrl}" target="_blank" class="snapshot-link">
                                        <span class="snap-date">${this.formatTimestamp(snap.timestamp)}</span>
                                        <span class="snap-status status-${snap.statusCode}">${snap.statusCode}</span>
                                        <span class="snap-size">${this.formatSize(snap.size)}</span>
                                    </a>
                                `).join('')}
                                ${grouped[year].length > 20 ? `<span class="more-snapshots">+${grouped[year].length - 20} more</span>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>

                <div class="wayback-actions">
                    <a href="https://web.archive.org/web/*/${url}" target="_blank" class="action-btn">
                        🔍 Browse all snapshots
                    </a>
                    <a href="https://web.archive.org/save/${url}" target="_blank" class="action-btn">
                        💾 Save new snapshot
                    </a>
                    <a href="https://web.archive.org/web/diff/*/${url}" target="_blank" class="action-btn">
                        📊 View changes
                    </a>
                </div>
            </div>
        `;
    }

    async checkCurrentPage() {
        const tab = await marshall.tabs.getCurrent();
        const url = tab.url;

        if (url.startsWith('marshall://') || url.startsWith('file://')) {
            marshall.ui.notify('Cannot check archive for local pages', 'warning');
            return;
        }

        marshall.ui.showPanel('<div class="wayback-loading">📜 Searching archives...</div>');

        const [snapshots, closest] = await Promise.all([
            this.getSnapshots(url),
            this.getClosestSnapshot(url)
        ]);

        marshall.ui.showPanel(this.formatResult(url, snapshots, closest), {
            title: 'Wayback Machine',
            width: 550,
            height: 650
        });
    }

    async contextMenuHandler(info) {
        const url = info.linkUrl || info.pageUrl;
        
        marshall.ui.showPanel('<div class="wayback-loading">📜 Searching archives...</div>');

        const [snapshots, closest] = await Promise.all([
            this.getSnapshots(url),
            this.getClosestSnapshot(url)
        ]);

        marshall.ui.showPanel(this.formatResult(url, snapshots, closest), {
            title: 'Wayback Machine',
            width: 550,
            height: 650
        });
    }

    async autoCheckHandler(tab) {
        if (tab.url.startsWith('marshall://') || tab.url.startsWith('file://')) {
            return;
        }

        const closest = await this.getClosestSnapshot(tab.url);
        if (closest) {
            marshall.toolbar.updateButton('wayback-btn', {
                badge: '✓',
                badgeColor: '#4CAF50'
            });
        } else {
            marshall.toolbar.updateButton('wayback-btn', {
                badge: '',
                badgeColor: ''
            });
        }
    }
}

// Extension entry point
const waybackMachine = new WaybackMachine();

marshall.extension.onActivate(async () => {
    await waybackMachine.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Wayback Machine] Extension deactivated');
});

// Export for API access
marshall.extension.export('getSnapshots', (url) => waybackMachine.getSnapshots(url));
marshall.extension.export('getClosest', (url) => waybackMachine.getClosestSnapshot(url));
