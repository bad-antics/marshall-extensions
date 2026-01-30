/**
 * Fingerprint Defender Extension for Marshall Browser
 * Protect against browser fingerprinting techniques
 * Part of Marshall Extensions Collection
 */

class FingerprintDefender {
    constructor() {
        this.settings = {
            block_canvas: true,
            block_webgl: true,
            block_audio: true,
            spoof_navigator: true,
            show_alerts: false
        };

        this.stats = {
            canvas: 0,
            webgl: 0,
            audio: 0,
            navigator: 0,
            fonts: 0,
            total: 0
        };

        this.blockedSites = new Map();

        this.spoofedNavigator = {
            platform: 'Win32',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            language: 'en-US',
            languages: ['en-US', 'en'],
            hardwareConcurrency: 4,
            deviceMemory: 8,
            maxTouchPoints: 0
        };
    }

    async init() {
        const savedSettings = await marshall.storage.get('settings');
        if (savedSettings) {
            this.settings = { ...this.settings, ...savedSettings };
        }

        this.injectProtections();

        marshall.toolbar.register({
            id: 'fingerprint-defender',
            title: 'Fingerprint Defender',
            icon: '🛡️',
            badge: () => this.stats.total.toString(),
            onclick: () => this.showDashboard()
        });

        marshall.keyboard.register('Ctrl+Shift+F', () => this.showDashboard());

        console.log('[Fingerprint Defender] Extension initialized');
        return true;
    }

    injectProtections() {
        const script = `
            (function() {
                const defender = {
                    log: (type, detail) => {
                        window.postMessage({ type: 'fingerprint-blocked', fingerprint: type, detail }, '*');
                    }
                };

                // Canvas fingerprint protection
                if (${this.settings.block_canvas}) {
                    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                    const originalToBlob = HTMLCanvasElement.prototype.toBlob;

                    HTMLCanvasElement.prototype.toDataURL = function(...args) {
                        defender.log('canvas', 'toDataURL called');
                        // Add subtle noise to prevent fingerprinting
                        const ctx = this.getContext('2d');
                        if (ctx) {
                            const imageData = ctx.getImageData(0, 0, this.width, this.height);
                            for (let i = 0; i < imageData.data.length; i += 4) {
                                imageData.data[i] ^= Math.random() < 0.01 ? 1 : 0;
                            }
                            ctx.putImageData(imageData, 0, 0);
                        }
                        return originalToDataURL.apply(this, args);
                    };

                    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
                        defender.log('canvas', 'getImageData called');
                        const imageData = originalGetImageData.apply(this, args);
                        // Add noise
                        for (let i = 0; i < imageData.data.length; i += 4) {
                            imageData.data[i] ^= Math.random() < 0.01 ? 1 : 0;
                        }
                        return imageData;
                    };
                }

                // WebGL fingerprint protection
                if (${this.settings.block_webgl}) {
                    const getParameterOrig = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(param) {
                        // Spoof common fingerprinting parameters
                        const spoofed = {
                            37445: 'Intel Inc.',  // UNMASKED_VENDOR_WEBGL
                            37446: 'Intel Iris OpenGL Engine', // UNMASKED_RENDERER_WEBGL
                        };
                        if (spoofed[param]) {
                            defender.log('webgl', 'getParameter(' + param + ') spoofed');
                            return spoofed[param];
                        }
                        return getParameterOrig.call(this, param);
                    };

                    // WebGL2 protection
                    if (window.WebGL2RenderingContext) {
                        const getParameter2Orig = WebGL2RenderingContext.prototype.getParameter;
                        WebGL2RenderingContext.prototype.getParameter = function(param) {
                            const spoofed = {
                                37445: 'Intel Inc.',
                                37446: 'Intel Iris OpenGL Engine',
                            };
                            if (spoofed[param]) {
                                defender.log('webgl2', 'getParameter(' + param + ') spoofed');
                                return spoofed[param];
                            }
                            return getParameter2Orig.call(this, param);
                        };
                    }
                }

                // AudioContext fingerprint protection
                if (${this.settings.block_audio}) {
                    const AudioContextOrig = window.AudioContext || window.webkitAudioContext;
                    if (AudioContextOrig) {
                        const createOscillator = AudioContextOrig.prototype.createOscillator;
                        const createDynamicsCompressor = AudioContextOrig.prototype.createDynamicsCompressor;

                        AudioContextOrig.prototype.createOscillator = function() {
                            defender.log('audio', 'createOscillator called');
                            const osc = createOscillator.call(this);
                            // Slightly modify frequency
                            const origFreq = osc.frequency;
                            return osc;
                        };

                        // Override destination to add noise
                        const getDestination = Object.getOwnPropertyDescriptor(AudioContextOrig.prototype, 'destination');
                        if (getDestination) {
                            Object.defineProperty(AudioContextOrig.prototype, 'destination', {
                                get: function() {
                                    defender.log('audio', 'destination accessed');
                                    return getDestination.get.call(this);
                                }
                            });
                        }
                    }
                }

                // Navigator property spoofing
                if (${this.settings.spoof_navigator}) {
                    const spoofedProps = ${JSON.stringify(this.spoofedNavigator)};
                    
                    for (const [prop, value] of Object.entries(spoofedProps)) {
                        try {
                            Object.defineProperty(navigator, prop, {
                                get: () => {
                                    defender.log('navigator', prop + ' spoofed');
                                    return value;
                                },
                                configurable: true
                            });
                        } catch (e) {}
                    }

                    // Spoof plugins
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => {
                            defender.log('navigator', 'plugins spoofed');
                            return [];
                        }
                    });
                }

                // Battery API protection
                if (navigator.getBattery) {
                    navigator.getBattery = () => {
                        defender.log('battery', 'getBattery blocked');
                        return Promise.reject(new Error('Battery API blocked'));
                    };
                }

                // Screen property randomization
                const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
                for (const prop of screenProps) {
                    try {
                        const original = screen[prop];
                        Object.defineProperty(screen, prop, {
                            get: () => {
                                // Return slightly modified values
                                return typeof original === 'number' ? original - (original % 10) : original;
                            }
                        });
                    } catch (e) {}
                }
            })();
        `;

        marshall.content.inject(script, { allFrames: true, runAt: 'document_start' });

        // Listen for fingerprinting attempts
        marshall.content.onMessage((msg) => {
            if (msg.type === 'fingerprint-blocked') {
                this.recordBlock(msg.fingerprint, msg.detail);
            }
        });
    }

    recordBlock(type, detail) {
        this.stats[type] = (this.stats[type] || 0) + 1;
        this.stats.total++;

        const url = marshall.tabs.getCurrentSync()?.url || 'unknown';
        const domain = new URL(url).hostname;

        if (!this.blockedSites.has(domain)) {
            this.blockedSites.set(domain, { canvas: 0, webgl: 0, audio: 0, navigator: 0, fonts: 0 });
        }
        this.blockedSites.get(domain)[type]++;

        if (this.settings.show_alerts) {
            marshall.ui.notify(`Blocked ${type} fingerprinting`, 'info');
        }
    }

    formatDashboard() {
        const topSites = Array.from(this.blockedSites.entries())
            .sort((a, b) => Object.values(b[1]).reduce((s, v) => s + v, 0) - Object.values(a[1]).reduce((s, v) => s + v, 0))
            .slice(0, 10);

        return `
            <div class="fingerprint-defender">
                <div class="defender-header">
                    <h2>🛡️ Fingerprint Defender</h2>
                    <span class="defender-status ${this.stats.total > 0 ? 'active' : ''}">
                        ${this.stats.total > 0 ? '🟢 Active' : '⚪ Monitoring'}
                    </span>
                </div>

                <div class="defender-stats-grid">
                    <div class="stat-card">
                        <span class="stat-icon">🎨</span>
                        <span class="stat-value">${this.stats.canvas}</span>
                        <span class="stat-label">Canvas</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-icon">🖼️</span>
                        <span class="stat-value">${this.stats.webgl}</span>
                        <span class="stat-label">WebGL</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-icon">🔊</span>
                        <span class="stat-value">${this.stats.audio}</span>
                        <span class="stat-label">Audio</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-icon">🧭</span>
                        <span class="stat-value">${this.stats.navigator}</span>
                        <span class="stat-label">Navigator</span>
                    </div>
                </div>

                <div class="defender-section">
                    <h3>⚙️ Protection Settings</h3>
                    <div class="settings-grid">
                        <label class="setting-item">
                            <input type="checkbox" ${this.settings.block_canvas ? 'checked' : ''} 
                                   onchange="defender.toggleSetting('block_canvas', this.checked)">
                            <span>🎨 Canvas Protection</span>
                            <small>Adds noise to canvas fingerprinting attempts</small>
                        </label>
                        <label class="setting-item">
                            <input type="checkbox" ${this.settings.block_webgl ? 'checked' : ''} 
                                   onchange="defender.toggleSetting('block_webgl', this.checked)">
                            <span>🖼️ WebGL Protection</span>
                            <small>Spoofs GPU/renderer information</small>
                        </label>
                        <label class="setting-item">
                            <input type="checkbox" ${this.settings.block_audio ? 'checked' : ''} 
                                   onchange="defender.toggleSetting('block_audio', this.checked)">
                            <span>🔊 Audio Protection</span>
                            <small>Protects AudioContext fingerprinting</small>
                        </label>
                        <label class="setting-item">
                            <input type="checkbox" ${this.settings.spoof_navigator ? 'checked' : ''} 
                                   onchange="defender.toggleSetting('spoof_navigator', this.checked)">
                            <span>🧭 Navigator Spoofing</span>
                            <small>Returns generic navigator properties</small>
                        </label>
                        <label class="setting-item">
                            <input type="checkbox" ${this.settings.show_alerts ? 'checked' : ''} 
                                   onchange="defender.toggleSetting('show_alerts', this.checked)">
                            <span>🔔 Show Alerts</span>
                            <small>Notify when fingerprinting is blocked</small>
                        </label>
                    </div>
                </div>

                <div class="defender-section">
                    <h3>🌐 Top Fingerprinting Sites</h3>
                    ${topSites.length > 0 ? `
                        <table class="sites-table">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Canvas</th>
                                    <th>WebGL</th>
                                    <th>Audio</th>
                                    <th>Navigator</th>
                                    <th>Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${topSites.map(([domain, stats]) => {
                                    const total = Object.values(stats).reduce((s, v) => s + v, 0);
                                    return `
                                        <tr>
                                            <td>${domain}</td>
                                            <td>${stats.canvas || 0}</td>
                                            <td>${stats.webgl || 0}</td>
                                            <td>${stats.audio || 0}</td>
                                            <td>${stats.navigator || 0}</td>
                                            <td><strong>${total}</strong></td>
                                        </tr>
                                    `;
                                }).join('')}
                            </tbody>
                        </table>
                    ` : '<p class="no-data">No fingerprinting attempts recorded yet</p>'}
                </div>

                <div class="defender-section">
                    <h3>🎭 Current Spoofed Identity</h3>
                    <div class="identity-card">
                        <div class="identity-row">
                            <span class="label">User Agent:</span>
                            <span class="value">${this.spoofedNavigator.userAgent}</span>
                        </div>
                        <div class="identity-row">
                            <span class="label">Platform:</span>
                            <span class="value">${this.spoofedNavigator.platform}</span>
                        </div>
                        <div class="identity-row">
                            <span class="label">Language:</span>
                            <span class="value">${this.spoofedNavigator.language}</span>
                        </div>
                        <div class="identity-row">
                            <span class="label">CPU Cores:</span>
                            <span class="value">${this.spoofedNavigator.hardwareConcurrency}</span>
                        </div>
                        <div class="identity-row">
                            <span class="label">Memory:</span>
                            <span class="value">${this.spoofedNavigator.deviceMemory} GB</span>
                        </div>
                    </div>
                    <button onclick="defender.randomizeIdentity()" class="randomize-btn">🎲 Randomize Identity</button>
                </div>

                <div class="defender-section">
                    <h3>🧪 Test Your Fingerprint</h3>
                    <div class="test-links">
                        <a href="https://browserleaks.com/canvas" target="_blank">Canvas Test</a>
                        <a href="https://browserleaks.com/webgl" target="_blank">WebGL Test</a>
                        <a href="https://audiofingerprint.openwpm.com/" target="_blank">Audio Test</a>
                        <a href="https://amiunique.org/" target="_blank">Am I Unique?</a>
                    </div>
                </div>
            </div>
        `;
    }

    async toggleSetting(key, value) {
        this.settings[key] = value;
        await marshall.storage.set('settings', this.settings);
        marshall.ui.notify(`${key.replace('_', ' ')} ${value ? 'enabled' : 'disabled'}`, 'info');
        // Reinject protections
        this.injectProtections();
    }

    randomizeIdentity() {
        const platforms = ['Win32', 'Linux x86_64', 'MacIntel'];
        const cores = [2, 4, 8, 16];
        const memory = [2, 4, 8, 16];

        this.spoofedNavigator.platform = platforms[Math.floor(Math.random() * platforms.length)];
        this.spoofedNavigator.hardwareConcurrency = cores[Math.floor(Math.random() * cores.length)];
        this.spoofedNavigator.deviceMemory = memory[Math.floor(Math.random() * memory.length)];

        this.injectProtections();
        marshall.ui.notify('Identity randomized', 'success');
        marshall.ui.updatePanel(this.formatDashboard());
    }

    showDashboard() {
        marshall.ui.showPanel(this.formatDashboard(), {
            title: 'Fingerprint Defender',
            width: 650,
            height: 700
        });
    }
}

const defender = new FingerprintDefender();

marshall.extension.onActivate(async () => {
    await defender.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Fingerprint Defender] Extension deactivated');
});

marshall.extension.export('stats', () => defender.stats);
marshall.extension.export('toggleProtection', (type, enabled) => defender.toggleSetting(type, enabled));
