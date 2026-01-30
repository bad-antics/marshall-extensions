/**
 * Extension Manager for Marshall Browser
 * Manage, enable/disable, and configure all installed extensions
 * Part of Marshall Extensions Collection
 */

class ExtensionManager {
    constructor() {
        this.extensions = new Map();
        this.categories = {
            recon: { name: 'Reconnaissance', icon: '🔍', color: '#00ff88' },
            privacy: { name: 'Privacy', icon: '🛡️', color: '#ff6b6b' },
            security: { name: 'Security', icon: '🔐', color: '#ffd93d' },
            forensics: { name: 'Forensics', icon: '🔬', color: '#6bcfff' },
            network: { name: 'Network', icon: '🌐', color: '#c9a0ff' },
            utility: { name: 'Utilities', icon: '🔧', color: '#ff9f43' }
        };
        this.searchQuery = '';
        this.filterCategory = 'all';
        this.sortBy = 'name';
    }

    async init() {
        await this.loadExtensions();

        marshall.keyboard.register('Ctrl+Shift+E', () => this.showManager());

        marshall.toolbar.register({
            id: 'extension-manager',
            title: 'Extension Manager',
            icon: '🧩',
            onclick: () => this.showManager()
        });

        // Register menu item
        marshall.menu.register({
            id: 'extensions-menu',
            title: 'Extensions',
            submenu: [
                { id: 'manage-extensions', title: '🧩 Manage Extensions', onclick: () => this.showManager() },
                { type: 'separator' },
                { id: 'reload-extensions', title: '🔄 Reload All', onclick: () => this.reloadAll() },
                { id: 'disable-all', title: '⏸️ Disable All', onclick: () => this.disableAll() },
                { id: 'enable-all', title: '▶️ Enable All', onclick: () => this.enableAll() }
            ]
        });

        console.log('[Extension Manager] Initialized with', this.extensions.size, 'extensions');
        return true;
    }

    async loadExtensions() {
        const installed = await marshall.extensions.getAll();
        
        for (const ext of installed) {
            const manifest = await marshall.extensions.getManifest(ext.id);
            const state = await marshall.storage.get(`ext_state_${ext.id}`) || { enabled: true };
            
            this.extensions.set(ext.id, {
                id: ext.id,
                name: manifest.name || ext.id,
                version: manifest.version || '1.0.0',
                description: manifest.description || 'No description',
                author: manifest.author || 'Unknown',
                category: manifest.category || 'utility',
                permissions: manifest.permissions || [],
                keywords: manifest.keywords || [],
                homepage: manifest.homepage || null,
                icon: manifest.icon || null,
                settings: manifest.settings || {},
                enabled: state.enabled,
                loaded: ext.loaded,
                path: ext.path
            });
        }
    }

    async toggleExtension(extId) {
        const ext = this.extensions.get(extId);
        if (!ext) return;

        ext.enabled = !ext.enabled;
        await marshall.storage.set(`ext_state_${extId}`, { enabled: ext.enabled });

        if (ext.enabled) {
            await marshall.extensions.enable(extId);
            marshall.ui.notify(`${ext.name} enabled`, 'success');
        } else {
            await marshall.extensions.disable(extId);
            marshall.ui.notify(`${ext.name} disabled`, 'info');
        }

        this.updateUI();
    }

    async reloadExtension(extId) {
        const ext = this.extensions.get(extId);
        if (!ext) return;

        await marshall.extensions.reload(extId);
        marshall.ui.notify(`${ext.name} reloaded`, 'success');
    }

    async uninstallExtension(extId) {
        const ext = this.extensions.get(extId);
        if (!ext) return;

        const confirmed = await marshall.ui.confirm({
            title: 'Uninstall Extension',
            message: `Are you sure you want to uninstall "${ext.name}"?`,
            confirmText: 'Uninstall',
            cancelText: 'Cancel'
        });

        if (confirmed) {
            await marshall.extensions.uninstall(extId);
            this.extensions.delete(extId);
            marshall.ui.notify(`${ext.name} uninstalled`, 'success');
            this.updateUI();
        }
    }

    async openSettings(extId) {
        const ext = this.extensions.get(extId);
        if (!ext || !ext.settings || Object.keys(ext.settings).length === 0) {
            marshall.ui.notify('This extension has no configurable settings', 'info');
            return;
        }

        const savedSettings = await marshall.storage.get(`ext_settings_${extId}`) || {};
        const currentSettings = { ...ext.settings, ...savedSettings };

        const settingsHtml = `
            <div class="ext-settings-panel">
                <h3>⚙️ ${ext.name} Settings</h3>
                <div class="settings-form">
                    ${Object.entries(ext.settings).map(([key, defaultVal]) => {
                        const value = currentSettings[key] ?? defaultVal;
                        const type = typeof defaultVal;
                        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

                        if (type === 'boolean') {
                            return `
                                <label class="setting-row checkbox">
                                    <input type="checkbox" data-key="${key}" ${value ? 'checked' : ''}>
                                    <span>${label}</span>
                                </label>
                            `;
                        } else if (type === 'number') {
                            return `
                                <label class="setting-row">
                                    <span>${label}</span>
                                    <input type="number" data-key="${key}" value="${value}">
                                </label>
                            `;
                        } else if (Array.isArray(defaultVal)) {
                            return `
                                <label class="setting-row">
                                    <span>${label}</span>
                                    <input type="text" data-key="${key}" value="${(value || []).join(', ')}" 
                                           placeholder="Comma-separated values">
                                </label>
                            `;
                        } else {
                            return `
                                <label class="setting-row">
                                    <span>${label}</span>
                                    <input type="text" data-key="${key}" value="${value || ''}">
                                </label>
                            `;
                        }
                    }).join('')}
                </div>
                <div class="settings-actions">
                    <button onclick="extManager.saveSettings('${extId}')" class="primary">💾 Save</button>
                    <button onclick="extManager.resetSettings('${extId}')">🔄 Reset</button>
                    <button onclick="marshall.ui.closePanel()">Cancel</button>
                </div>
            </div>
        `;

        marshall.ui.showPanel(settingsHtml, {
            title: `${ext.name} Settings`,
            width: 450,
            height: 400
        });
    }

    async saveSettings(extId) {
        const ext = this.extensions.get(extId);
        if (!ext) return;

        const settings = {};
        document.querySelectorAll('.settings-form [data-key]').forEach(input => {
            const key = input.dataset.key;
            const type = typeof ext.settings[key];

            if (input.type === 'checkbox') {
                settings[key] = input.checked;
            } else if (type === 'number') {
                settings[key] = parseFloat(input.value) || 0;
            } else if (Array.isArray(ext.settings[key])) {
                settings[key] = input.value.split(',').map(s => s.trim()).filter(s => s);
            } else {
                settings[key] = input.value;
            }
        });

        await marshall.storage.set(`ext_settings_${extId}`, settings);
        await marshall.extensions.updateSettings(extId, settings);
        
        marshall.ui.notify('Settings saved', 'success');
        marshall.ui.closePanel();
    }

    async resetSettings(extId) {
        await marshall.storage.remove(`ext_settings_${extId}`);
        marshall.ui.notify('Settings reset to defaults', 'info');
        this.openSettings(extId);
    }

    async enableAll() {
        for (const [id, ext] of this.extensions) {
            if (!ext.enabled) {
                ext.enabled = true;
                await marshall.storage.set(`ext_state_${id}`, { enabled: true });
                await marshall.extensions.enable(id);
            }
        }
        marshall.ui.notify('All extensions enabled', 'success');
        this.updateUI();
    }

    async disableAll() {
        for (const [id, ext] of this.extensions) {
            if (ext.enabled && ext.name !== 'extension-manager') {
                ext.enabled = false;
                await marshall.storage.set(`ext_state_${id}`, { enabled: false });
                await marshall.extensions.disable(id);
            }
        }
        marshall.ui.notify('All extensions disabled', 'info');
        this.updateUI();
    }

    async reloadAll() {
        for (const [id] of this.extensions) {
            await marshall.extensions.reload(id);
        }
        marshall.ui.notify('All extensions reloaded', 'success');
    }

    getFilteredExtensions() {
        let exts = Array.from(this.extensions.values());

        // Filter by category
        if (this.filterCategory !== 'all') {
            exts = exts.filter(e => e.category === this.filterCategory);
        }

        // Filter by search
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            exts = exts.filter(e => 
                e.name.toLowerCase().includes(q) ||
                e.description.toLowerCase().includes(q) ||
                (e.keywords || []).some(k => k.toLowerCase().includes(q))
            );
        }

        // Sort
        switch (this.sortBy) {
            case 'name':
                exts.sort((a, b) => a.name.localeCompare(b.name));
                break;
            case 'category':
                exts.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
                break;
            case 'status':
                exts.sort((a, b) => (b.enabled ? 1 : 0) - (a.enabled ? 1 : 0));
                break;
        }

        return exts;
    }

    getStats() {
        const exts = Array.from(this.extensions.values());
        return {
            total: exts.length,
            enabled: exts.filter(e => e.enabled).length,
            disabled: exts.filter(e => !e.enabled).length,
            byCategory: Object.keys(this.categories).reduce((acc, cat) => {
                acc[cat] = exts.filter(e => e.category === cat).length;
                return acc;
            }, {})
        };
    }

    formatExtensionCard(ext) {
        const cat = this.categories[ext.category] || this.categories.utility;
        const hasSettings = ext.settings && Object.keys(ext.settings).length > 0;

        return `
            <div class="ext-card ${ext.enabled ? 'enabled' : 'disabled'}" data-id="${ext.id}">
                <div class="ext-header">
                    <div class="ext-icon" style="background: ${cat.color}20; color: ${cat.color}">
                        ${cat.icon}
                    </div>
                    <div class="ext-info">
                        <h4 class="ext-name">${ext.name}</h4>
                        <span class="ext-version">v${ext.version}</span>
                    </div>
                    <label class="ext-toggle">
                        <input type="checkbox" ${ext.enabled ? 'checked' : ''} 
                               onchange="extManager.toggleExtension('${ext.id}')">
                        <span class="toggle-slider"></span>
                    </label>
                </div>
                <p class="ext-description">${ext.description}</p>
                <div class="ext-meta">
                    <span class="ext-category" style="background: ${cat.color}20; color: ${cat.color}">
                        ${cat.icon} ${cat.name}
                    </span>
                    <span class="ext-author">by ${ext.author}</span>
                </div>
                <div class="ext-permissions">
                    ${ext.permissions.slice(0, 4).map(p => `<span class="perm-badge">${p}</span>`).join('')}
                    ${ext.permissions.length > 4 ? `<span class="perm-badge more">+${ext.permissions.length - 4}</span>` : ''}
                </div>
                <div class="ext-actions">
                    ${hasSettings ? `<button onclick="extManager.openSettings('${ext.id}')" title="Settings">⚙️</button>` : ''}
                    <button onclick="extManager.reloadExtension('${ext.id}')" title="Reload">🔄</button>
                    ${ext.homepage ? `<button onclick="marshall.tabs.create({url:'${ext.homepage}'})" title="Homepage">🏠</button>` : ''}
                    <button onclick="extManager.uninstallExtension('${ext.id}')" title="Uninstall" class="danger">🗑️</button>
                </div>
            </div>
        `;
    }

    formatManager() {
        const stats = this.getStats();
        const filtered = this.getFilteredExtensions();

        return `
            <div class="extension-manager">
                <div class="manager-header">
                    <h2>🧩 Extension Manager</h2>
                    <div class="header-stats">
                        <span class="stat enabled">${stats.enabled} enabled</span>
                        <span class="stat disabled">${stats.disabled} disabled</span>
                        <span class="stat total">${stats.total} total</span>
                    </div>
                </div>

                <div class="manager-toolbar">
                    <div class="search-box">
                        <input type="text" id="ext-search" placeholder="🔍 Search extensions..." 
                               value="${this.searchQuery}"
                               oninput="extManager.setSearch(this.value)">
                    </div>
                    <div class="filter-controls">
                        <select id="category-filter" onchange="extManager.setCategory(this.value)">
                            <option value="all" ${this.filterCategory === 'all' ? 'selected' : ''}>All Categories</option>
                            ${Object.entries(this.categories).map(([key, cat]) => `
                                <option value="${key}" ${this.filterCategory === key ? 'selected' : ''}>
                                    ${cat.icon} ${cat.name} (${stats.byCategory[key] || 0})
                                </option>
                            `).join('')}
                        </select>
                        <select id="sort-by" onchange="extManager.setSort(this.value)">
                            <option value="name" ${this.sortBy === 'name' ? 'selected' : ''}>Sort by Name</option>
                            <option value="category" ${this.sortBy === 'category' ? 'selected' : ''}>Sort by Category</option>
                            <option value="status" ${this.sortBy === 'status' ? 'selected' : ''}>Sort by Status</option>
                        </select>
                    </div>
                </div>

                <div class="manager-actions">
                    <button onclick="extManager.enableAll()" class="action-btn">▶️ Enable All</button>
                    <button onclick="extManager.disableAll()" class="action-btn">⏸️ Disable All</button>
                    <button onclick="extManager.reloadAll()" class="action-btn">🔄 Reload All</button>
                    <button onclick="extManager.checkUpdates()" class="action-btn">📥 Check Updates</button>
                </div>

                <div class="category-tabs">
                    <button class="tab ${this.filterCategory === 'all' ? 'active' : ''}" 
                            onclick="extManager.setCategory('all')">
                        All (${stats.total})
                    </button>
                    ${Object.entries(this.categories).map(([key, cat]) => `
                        <button class="tab ${this.filterCategory === key ? 'active' : ''}" 
                                onclick="extManager.setCategory('${key}')"
                                style="${this.filterCategory === key ? `border-color: ${cat.color}` : ''}">
                            ${cat.icon} ${cat.name} (${stats.byCategory[key] || 0})
                        </button>
                    `).join('')}
                </div>

                <div class="extensions-grid" id="extensions-grid">
                    ${filtered.length > 0 ? 
                        filtered.map(ext => this.formatExtensionCard(ext)).join('') :
                        `<div class="no-results">
                            <span class="icon">🔍</span>
                            <p>No extensions found matching your criteria</p>
                        </div>`
                    }
                </div>

                <div class="manager-footer">
                    <span>Extension Directory: ~/.local/share/marshall/extensions</span>
                    <button onclick="extManager.openExtensionFolder()">📂 Open Folder</button>
                </div>
            </div>

            <style>
                .extension-manager {
                    font-family: 'JetBrains Mono', monospace;
                    background: #1a1a2e;
                    color: #e0e0e0;
                    padding: 20px;
                    height: 100%;
                    overflow-y: auto;
                }
                .manager-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 1px solid #333;
                }
                .manager-header h2 { margin: 0; color: #00ff88; }
                .header-stats { display: flex; gap: 15px; }
                .header-stats .stat {
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 12px;
                }
                .stat.enabled { background: #00ff8820; color: #00ff88; }
                .stat.disabled { background: #ff6b6b20; color: #ff6b6b; }
                .stat.total { background: #6bcfff20; color: #6bcfff; }

                .manager-toolbar {
                    display: flex;
                    gap: 15px;
                    margin-bottom: 15px;
                }
                .search-box { flex: 1; }
                .search-box input {
                    width: 100%;
                    padding: 10px 15px;
                    background: #252542;
                    border: 1px solid #333;
                    border-radius: 6px;
                    color: #fff;
                    font-size: 14px;
                }
                .filter-controls { display: flex; gap: 10px; }
                .filter-controls select {
                    padding: 10px;
                    background: #252542;
                    border: 1px solid #333;
                    border-radius: 6px;
                    color: #fff;
                    cursor: pointer;
                }

                .manager-actions {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 15px;
                }
                .action-btn {
                    padding: 8px 15px;
                    background: #252542;
                    border: 1px solid #444;
                    border-radius: 6px;
                    color: #fff;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .action-btn:hover { background: #333; border-color: #00ff88; }

                .category-tabs {
                    display: flex;
                    gap: 5px;
                    margin-bottom: 20px;
                    flex-wrap: wrap;
                }
                .category-tabs .tab {
                    padding: 8px 15px;
                    background: transparent;
                    border: 1px solid #333;
                    border-radius: 20px;
                    color: #888;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .category-tabs .tab:hover { color: #fff; border-color: #555; }
                .category-tabs .tab.active {
                    background: #252542;
                    color: #fff;
                    border-color: #00ff88;
                }

                .extensions-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                    gap: 15px;
                }

                .ext-card {
                    background: #252542;
                    border: 1px solid #333;
                    border-radius: 10px;
                    padding: 15px;
                    transition: all 0.2s;
                }
                .ext-card:hover { border-color: #444; transform: translateY(-2px); }
                .ext-card.disabled { opacity: 0.6; }
                .ext-card.disabled .ext-icon { filter: grayscale(1); }

                .ext-header {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    margin-bottom: 10px;
                }
                .ext-icon {
                    width: 40px;
                    height: 40px;
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 20px;
                }
                .ext-info { flex: 1; }
                .ext-name { margin: 0; font-size: 15px; color: #fff; }
                .ext-version { font-size: 11px; color: #666; }

                .ext-toggle { position: relative; }
                .ext-toggle input { display: none; }
                .toggle-slider {
                    display: block;
                    width: 44px;
                    height: 24px;
                    background: #333;
                    border-radius: 12px;
                    cursor: pointer;
                    transition: all 0.2s;
                    position: relative;
                }
                .toggle-slider::after {
                    content: '';
                    position: absolute;
                    top: 3px;
                    left: 3px;
                    width: 18px;
                    height: 18px;
                    background: #666;
                    border-radius: 50%;
                    transition: all 0.2s;
                }
                .ext-toggle input:checked + .toggle-slider { background: #00ff8840; }
                .ext-toggle input:checked + .toggle-slider::after {
                    left: 23px;
                    background: #00ff88;
                }

                .ext-description {
                    font-size: 12px;
                    color: #888;
                    margin: 0 0 10px 0;
                    line-height: 1.4;
                }

                .ext-meta {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .ext-category {
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 11px;
                }
                .ext-author { font-size: 11px; color: #666; }

                .ext-permissions {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 5px;
                    margin-bottom: 12px;
                }
                .perm-badge {
                    padding: 2px 6px;
                    background: #1a1a2e;
                    border-radius: 3px;
                    font-size: 10px;
                    color: #888;
                }
                .perm-badge.more { color: #666; }

                .ext-actions {
                    display: flex;
                    gap: 8px;
                    border-top: 1px solid #333;
                    padding-top: 12px;
                }
                .ext-actions button {
                    flex: 1;
                    padding: 6px;
                    background: #1a1a2e;
                    border: 1px solid #333;
                    border-radius: 4px;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .ext-actions button:hover { background: #333; }
                .ext-actions button.danger:hover { background: #ff6b6b30; border-color: #ff6b6b; }

                .no-results {
                    grid-column: 1 / -1;
                    text-align: center;
                    padding: 60px 20px;
                    color: #666;
                }
                .no-results .icon { font-size: 48px; }

                .manager-footer {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-top: 20px;
                    padding-top: 15px;
                    border-top: 1px solid #333;
                    font-size: 12px;
                    color: #666;
                }
                .manager-footer button {
                    padding: 6px 12px;
                    background: transparent;
                    border: 1px solid #333;
                    border-radius: 4px;
                    color: #888;
                    cursor: pointer;
                }
                .manager-footer button:hover { border-color: #00ff88; color: #00ff88; }

                .ext-settings-panel { padding: 20px; }
                .ext-settings-panel h3 { margin: 0 0 20px 0; color: #00ff88; }
                .settings-form { display: flex; flex-direction: column; gap: 15px; }
                .setting-row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 10px;
                    background: #252542;
                    border-radius: 6px;
                }
                .setting-row.checkbox { cursor: pointer; }
                .setting-row input[type="text"],
                .setting-row input[type="number"] {
                    padding: 8px;
                    background: #1a1a2e;
                    border: 1px solid #333;
                    border-radius: 4px;
                    color: #fff;
                    width: 200px;
                }
                .settings-actions {
                    display: flex;
                    gap: 10px;
                    margin-top: 20px;
                }
                .settings-actions button {
                    padding: 10px 20px;
                    background: #252542;
                    border: 1px solid #333;
                    border-radius: 6px;
                    color: #fff;
                    cursor: pointer;
                }
                .settings-actions button.primary { background: #00ff8830; border-color: #00ff88; }
            </style>
        `;
    }

    setSearch(query) {
        this.searchQuery = query;
        this.updateUI();
    }

    setCategory(category) {
        this.filterCategory = category;
        this.updateUI();
    }

    setSort(sortBy) {
        this.sortBy = sortBy;
        this.updateUI();
    }

    updateUI() {
        const grid = document.getElementById('extensions-grid');
        if (grid) {
            const filtered = this.getFilteredExtensions();
            grid.innerHTML = filtered.length > 0 ? 
                filtered.map(ext => this.formatExtensionCard(ext)).join('') :
                `<div class="no-results">
                    <span class="icon">🔍</span>
                    <p>No extensions found matching your criteria</p>
                </div>`;
        }
    }

    async checkUpdates() {
        marshall.ui.notify('Checking for updates...', 'info');
        // Would check remote repository for updates
        setTimeout(() => {
            marshall.ui.notify('All extensions are up to date', 'success');
        }, 1500);
    }

    openExtensionFolder() {
        marshall.system.openPath('~/.local/share/marshall/extensions');
    }

    showManager() {
        marshall.ui.showPanel(this.formatManager(), {
            title: 'Extension Manager',
            width: 900,
            height: 700
        });
    }
}

const extManager = new ExtensionManager();

marshall.extension.onActivate(async () => {
    await extManager.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Extension Manager] Deactivated');
});

// Export API for other extensions
marshall.extension.export('getAll', () => extManager.extensions);
marshall.extension.export('toggle', (id) => extManager.toggleExtension(id));
marshall.extension.export('reload', (id) => extManager.reloadExtension(id));
