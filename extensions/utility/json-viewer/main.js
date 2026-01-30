/**
 * JSON Viewer Extension for Marshall Browser
 * Beautiful JSON formatting and viewing
 * Part of Marshall Extensions Collection
 */

class JSONViewer {
    constructor() {
        this.theme = 'dark';
    }

    async init() {
        // Auto-format JSON responses
        marshall.network.onResponse((response) => {
            if (response.headers['content-type']?.includes('application/json')) {
                this.formatJsonPage(response);
            }
        });

        marshall.keyboard.register('Ctrl+Shift+J', () => this.showViewer());

        marshall.contextMenu.register({
            id: 'view-json',
            title: 'View as JSON',
            contexts: ['selection'],
            onclick: (info) => this.viewSelection(info)
        });

        console.log('[JSON Viewer] Extension initialized');
        return true;
    }

    formatJson(json, indent = 2) {
        try {
            const obj = typeof json === 'string' ? JSON.parse(json) : json;
            return JSON.stringify(obj, null, indent);
        } catch (e) {
            return null;
        }
    }

    syntaxHighlight(json) {
        if (typeof json !== 'string') {
            json = JSON.stringify(json, null, 2);
        }
        
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        
        return json.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
            (match) => {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'json-key';
                    } else {
                        cls = 'json-string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return `<span class="${cls}">${match}</span>`;
            }
        );
    }

    buildTree(obj, path = '') {
        if (obj === null) return '<span class="json-null">null</span>';
        if (typeof obj !== 'object') {
            if (typeof obj === 'string') return `<span class="json-string">"${this.escapeHtml(obj)}"</span>`;
            if (typeof obj === 'boolean') return `<span class="json-boolean">${obj}</span>`;
            return `<span class="json-number">${obj}</span>`;
        }

        const isArray = Array.isArray(obj);
        const entries = Object.entries(obj);
        const id = 'node-' + Math.random().toString(36).substr(2, 9);

        if (entries.length === 0) {
            return isArray ? '[]' : '{}';
        }

        return `
            <span class="json-bracket" onclick="document.getElementById('${id}').classList.toggle('collapsed')">
                ${isArray ? '[' : '{'}
            </span>
            <span class="json-collapse-btn" onclick="document.getElementById('${id}').classList.toggle('collapsed')">
                ▼
            </span>
            <div id="${id}" class="json-children">
                ${entries.map(([key, value], i) => `
                    <div class="json-line">
                        ${!isArray ? `<span class="json-key">"${key}"</span><span class="json-colon">: </span>` : ''}
                        ${this.buildTree(value, path + '.' + key)}${i < entries.length - 1 ? ',' : ''}
                    </div>
                `).join('')}
            </div>
            <span class="json-bracket">${isArray ? ']' : '}'}</span>
        `;
    }

    escapeHtml(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    getStats(obj) {
        let stats = { keys: 0, strings: 0, numbers: 0, booleans: 0, nulls: 0, arrays: 0, objects: 0, depth: 0 };
        
        const traverse = (o, depth = 0) => {
            stats.depth = Math.max(stats.depth, depth);
            
            if (o === null) { stats.nulls++; return; }
            if (typeof o !== 'object') {
                if (typeof o === 'string') stats.strings++;
                else if (typeof o === 'number') stats.numbers++;
                else if (typeof o === 'boolean') stats.booleans++;
                return;
            }
            
            if (Array.isArray(o)) {
                stats.arrays++;
                o.forEach(item => traverse(item, depth + 1));
            } else {
                stats.objects++;
                for (const [key, value] of Object.entries(o)) {
                    stats.keys++;
                    traverse(value, depth + 1);
                }
            }
        };
        
        traverse(obj);
        return stats;
    }

    formatResult(json, source = 'input') {
        let obj;
        try {
            obj = typeof json === 'string' ? JSON.parse(json) : json;
        } catch (e) {
            return `
                <div class="json-viewer">
                    <div class="json-error">
                        <h3>❌ Invalid JSON</h3>
                        <pre>${e.message}</pre>
                    </div>
                </div>
            `;
        }

        const stats = this.getStats(obj);
        const formatted = JSON.stringify(obj, null, 2);
        const size = new Blob([formatted]).size;

        return `
            <div class="json-viewer">
                <div class="json-header">
                    <h2>📋 JSON Viewer</h2>
                </div>

                <div class="json-toolbar">
                    <button onclick="jsonViewer.copyJson()" title="Copy">📋 Copy</button>
                    <button onclick="jsonViewer.downloadJson()" title="Download">💾 Save</button>
                    <button onclick="jsonViewer.toggleView()" title="Toggle View">🔄 Raw/Tree</button>
                    <button onclick="jsonViewer.collapseAll()" title="Collapse All">➖</button>
                    <button onclick="jsonViewer.expandAll()" title="Expand All">➕</button>
                    <input type="text" id="json-search" placeholder="🔍 Search..." oninput="jsonViewer.search(this.value)">
                </div>

                <div class="json-stats">
                    <span>📊 ${stats.keys} keys</span>
                    <span>📦 ${stats.objects} objects</span>
                    <span>📝 ${stats.arrays} arrays</span>
                    <span>📏 ${stats.depth} depth</span>
                    <span>💾 ${this.formatSize(size)}</span>
                </div>

                <div class="json-path" id="json-path">$</div>

                <div class="json-content" id="json-content">
                    <div class="json-tree" id="json-tree">
                        ${this.buildTree(obj)}
                    </div>
                    <pre class="json-raw" id="json-raw" style="display:none">${this.syntaxHighlight(formatted)}</pre>
                </div>
            </div>
        `;
    }

    formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    async showViewer(json = null) {
        if (!json) {
            // Try to get from clipboard or current page
            json = await marshall.clipboard.read();
        }

        marshall.ui.showPanel(this.formatResult(json), {
            title: 'JSON Viewer',
            width: 700,
            height: 600
        });
    }

    viewSelection(info) {
        this.showViewer(info.selectionText);
    }

    toggleView() {
        const tree = document.getElementById('json-tree');
        const raw = document.getElementById('json-raw');
        tree.style.display = tree.style.display === 'none' ? 'block' : 'none';
        raw.style.display = raw.style.display === 'none' ? 'block' : 'none';
    }

    collapseAll() {
        document.querySelectorAll('.json-children').forEach(el => el.classList.add('collapsed'));
    }

    expandAll() {
        document.querySelectorAll('.json-children').forEach(el => el.classList.remove('collapsed'));
    }

    search(query) {
        // Remove existing highlights
        document.querySelectorAll('.json-highlight').forEach(el => {
            el.outerHTML = el.innerHTML;
        });

        if (!query) return;

        const content = document.getElementById('json-content');
        const walker = document.createTreeWalker(content, NodeFilter.SHOW_TEXT);
        
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (node.textContent.toLowerCase().includes(query.toLowerCase())) {
                const span = document.createElement('span');
                span.className = 'json-highlight';
                span.innerHTML = node.textContent.replace(
                    new RegExp(`(${query})`, 'gi'),
                    '<mark>$1</mark>'
                );
                node.parentNode.replaceChild(span, node);
            }
        }
    }

    async copyJson() {
        const raw = document.getElementById('json-raw');
        await marshall.clipboard.write(raw.textContent);
        marshall.ui.notify('JSON copied to clipboard', 'success');
    }

    downloadJson() {
        const raw = document.getElementById('json-raw');
        marshall.download.save(raw.textContent, 'data.json', 'application/json');
    }

    formatJsonPage(response) {
        // Intercept JSON responses and format them
        try {
            const obj = JSON.parse(response.body);
            const formatted = this.formatResult(obj, response.url);
            marshall.tabs.setContent(formatted);
        } catch (e) {
            // Not valid JSON, let it pass through
        }
    }
}

const jsonViewer = new JSONViewer();

marshall.extension.onActivate(async () => {
    await jsonViewer.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[JSON Viewer] Extension deactivated');
});

marshall.extension.export('format', (json) => jsonViewer.formatJson(json));
marshall.extension.export('highlight', (json) => jsonViewer.syntaxHighlight(json));
