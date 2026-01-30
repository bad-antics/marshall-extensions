/**
 * Tech Detector Extension for Marshall Browser
 * Detect technologies used by websites
 * Part of Marshall Extensions Collection
 */

class TechDetector {
    constructor() {
        this.signatures = {
            cms: {
                'WordPress': { patterns: [/wp-content|wp-includes/i, /wordpress/i], icon: '📝' },
                'Drupal': { patterns: [/drupal/i, /sites\/all\/|sites\/default\//], icon: '💧' },
                'Joomla': { patterns: [/joomla/i, /\/components\/com_/], icon: '🟠' },
                'Ghost': { patterns: [/ghost/i, /\/ghost\//], icon: '👻' },
                'Shopify': { patterns: [/shopify/i, /cdn\.shopify\.com/], icon: '🛒' },
                'Squarespace': { patterns: [/squarespace/i], icon: '◼️' },
                'Wix': { patterns: [/wix\.com|wixsite\.com/i], icon: '��' },
                'Webflow': { patterns: [/webflow/i], icon: '🌊' }
            },
            frameworks: {
                'React': { patterns: [/__REACT|react\.production|reactjs/i, /data-reactroot/], icon: '⚛️' },
                'Vue.js': { patterns: [/vue\.js|vuejs/i, /data-v-[a-f0-9]/], icon: '💚' },
                'Angular': { patterns: [/angular/i, /ng-version|ng-app/], icon: '🔺' },
                'Next.js': { patterns: [/_next\/|__NEXT_DATA__/i], icon: '▲' },
                'Nuxt.js': { patterns: [/_nuxt\/|__NUXT__/i], icon: '💚' },
                'Svelte': { patterns: [/svelte/i], icon: '🔶' },
                'jQuery': { patterns: [/jquery/i], icon: '📜' },
                'Bootstrap': { patterns: [/bootstrap/i], icon: '🅱️' },
                'Tailwind': { patterns: [/tailwind/i], icon: '🌊' },
                'Laravel': { patterns: [/laravel/i], icon: '🔴' },
                'Django': { patterns: [/csrfmiddlewaretoken|django/i], icon: '🐍' },
                'Ruby on Rails': { patterns: [/rails|turbolinks/i], icon: '💎' },
                'Express': { patterns: [/x-powered-by:.*express/i], icon: '⚡' },
                'ASP.NET': { patterns: [/asp\.net|__VIEWSTATE/i], icon: '🔵' }
            },
            servers: {
                'nginx': { patterns: [/nginx/i], icon: '🟢' },
                'Apache': { patterns: [/apache/i], icon: '🪶' },
                'IIS': { patterns: [/iis|microsoft/i], icon: '🪟' },
                'Cloudflare': { patterns: [/cloudflare/i], icon: '☁️' },
                'AWS': { patterns: [/amazonaws|aws/i], icon: '☁️' },
                'Vercel': { patterns: [/vercel/i], icon: '▲' },
                'Netlify': { patterns: [/netlify/i], icon: '🌐' },
                'Heroku': { patterns: [/heroku/i], icon: '🟣' }
            },
            analytics: {
                'Google Analytics': { patterns: [/google-analytics|gtag|ga\.js|analytics\.js/i], icon: '📊' },
                'Google Tag Manager': { patterns: [/googletagmanager/i], icon: '🏷️' },
                'Facebook Pixel': { patterns: [/fbevents|facebook.*pixel/i], icon: '📘' },
                'Hotjar': { patterns: [/hotjar/i], icon: '🔥' },
                'Mixpanel': { patterns: [/mixpanel/i], icon: '📈' },
                'Segment': { patterns: [/segment\.com|analytics\.js/i], icon: '📊' },
                'Plausible': { patterns: [/plausible/i], icon: '📈' },
                'Matomo': { patterns: [/matomo|piwik/i], icon: '📊' }
            },
            security: {
                'reCAPTCHA': { patterns: [/recaptcha/i], icon: '🤖' },
                'hCaptcha': { patterns: [/hcaptcha/i], icon: '🛡️' },
                'Cloudflare Bot Protection': { patterns: [/cf-ray|__cf_bm/i], icon: '🛡️' },
                'SSL/TLS': { patterns: [/https:/i], icon: '🔒' }
            },
            ecommerce: {
                'WooCommerce': { patterns: [/woocommerce/i], icon: '🛍️' },
                'Magento': { patterns: [/magento|mage/i], icon: '🟠' },
                'PrestaShop': { patterns: [/prestashop/i], icon: '🛒' },
                'BigCommerce': { patterns: [/bigcommerce/i], icon: '🛒' },
                'Stripe': { patterns: [/stripe\.js|js\.stripe\.com/i], icon: '💳' },
                'PayPal': { patterns: [/paypal/i], icon: '💰' }
            }
        };
    }

    async init() {
        marshall.toolbar.addButton({
            id: 'tech-detector-btn',
            icon: '🔍',
            tooltip: 'Detect Technologies',
            onclick: () => this.detectCurrentPage()
        });

        marshall.keyboard.register('Ctrl+Shift+T', () => this.detectCurrentPage());

        marshall.contextMenu.register({
            id: 'tech-detect',
            title: 'Detect Technologies',
            contexts: ['page'],
            onclick: () => this.detectCurrentPage()
        });

        marshall.tabs.onNavigate((tab) => this.autoDetect(tab));

        console.log('[Tech Detector] Extension initialized');
        return true;
    }

    async getPageData(tab) {
        const html = await marshall.tabs.executeScript(tab.id, {
            code: 'document.documentElement.outerHTML'
        });
        
        const headers = await marshall.network.getResponseHeaders(tab.url);
        const scripts = await marshall.tabs.executeScript(tab.id, {
            code: 'Array.from(document.scripts).map(s => s.src || s.innerHTML.substring(0, 500))'
        });
        const meta = await marshall.tabs.executeScript(tab.id, {
            code: `Array.from(document.querySelectorAll('meta')).map(m => ({name: m.name, content: m.content, property: m.getAttribute('property')}))`
        });

        return { html, headers, scripts, meta };
    }

    detect(data) {
        const detected = {};
        const searchText = [
            data.html || '',
            JSON.stringify(data.headers || {}),
            (data.scripts || []).join(' '),
            JSON.stringify(data.meta || [])
        ].join(' ');

        for (const [category, techs] of Object.entries(this.signatures)) {
            detected[category] = [];
            
            for (const [name, config] of Object.entries(techs)) {
                for (const pattern of config.patterns) {
                    if (pattern.test(searchText)) {
                        detected[category].push({
                            name,
                            icon: config.icon,
                            confidence: this.calculateConfidence(pattern, searchText)
                        });
                        break;
                    }
                }
            }
        }

        return detected;
    }

    calculateConfidence(pattern, text) {
        const matches = text.match(new RegExp(pattern.source, 'gi')) || [];
        if (matches.length > 5) return 'High';
        if (matches.length > 2) return 'Medium';
        return 'Low';
    }

    formatResult(url, detected) {
        const totalDetected = Object.values(detected).flat().length;

        return `
            <div class="tech-detector">
                <div class="tech-header">
                    <h2>🔍 Technology Detector</h2>
                    <span class="tech-url">${new URL(url).hostname}</span>
                </div>

                <div class="tech-summary">
                    <span class="tech-count">${totalDetected} technologies detected</span>
                </div>

                ${Object.entries(detected).map(([category, techs]) => techs.length > 0 ? `
                    <div class="tech-category">
                        <h3>${this.getCategoryTitle(category)}</h3>
                        <div class="tech-list">
                            ${techs.map(tech => `
                                <div class="tech-item">
                                    <span class="tech-icon">${tech.icon}</span>
                                    <span class="tech-name">${tech.name}</span>
                                    <span class="tech-confidence confidence-${tech.confidence.toLowerCase()}">${tech.confidence}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : '').join('')}

                ${totalDetected === 0 ? `
                    <div class="tech-empty">
                        <p>No technologies detected</p>
                        <small>The site may be using custom or uncommon technologies</small>
                    </div>
                ` : ''}

                <div class="tech-actions">
                    <button onclick="techDetector.exportReport('${url}')" class="action-btn">
                        📥 Export Report
                    </button>
                    <a href="https://builtwith.com/${new URL(url).hostname}" target="_blank" class="action-btn">
                        🔗 BuiltWith
                    </a>
                    <a href="https://www.wappalyzer.com/lookup/${new URL(url).hostname}" target="_blank" class="action-btn">
                        🔗 Wappalyzer
                    </a>
                </div>
            </div>
        `;
    }

    getCategoryTitle(category) {
        const titles = {
            cms: '📝 CMS / Platforms',
            frameworks: '🏗️ Frameworks & Libraries',
            servers: '🖥️ Servers & Hosting',
            analytics: '📊 Analytics & Tracking',
            security: '🔒 Security',
            ecommerce: '🛒 E-commerce'
        };
        return titles[category] || category;
    }

    async detectCurrentPage() {
        const tab = await marshall.tabs.getCurrent();
        
        if (tab.url.startsWith('marshall://') || tab.url.startsWith('file://')) {
            marshall.ui.notify('Cannot detect technologies on local pages', 'warning');
            return;
        }

        marshall.ui.showPanel('<div class="tech-loading">🔍 Analyzing page...</div>');

        try {
            const data = await this.getPageData(tab);
            const detected = this.detect(data);

            marshall.ui.showPanel(this.formatResult(tab.url, detected), {
                title: 'Tech Detector',
                width: 450,
                height: 600
            });

            // Update badge
            const total = Object.values(detected).flat().length;
            marshall.toolbar.updateButton('tech-detector-btn', {
                badge: total.toString(),
                badgeColor: '#2196F3'
            });
        } catch (error) {
            marshall.ui.notify('Error detecting technologies: ' + error.message, 'error');
        }
    }

    async autoDetect(tab) {
        if (tab.url.startsWith('marshall://') || tab.url.startsWith('file://')) {
            return;
        }

        try {
            const data = await this.getPageData(tab);
            const detected = this.detect(data);
            const total = Object.values(detected).flat().length;

            marshall.toolbar.updateButton('tech-detector-btn', {
                badge: total > 0 ? total.toString() : '',
                badgeColor: '#2196F3'
            });
        } catch (error) {
            // Silently fail for auto-detection
        }
    }

    async exportReport(url) {
        const tab = await marshall.tabs.getCurrent();
        const data = await this.getPageData(tab);
        const detected = this.detect(data);

        const report = {
            url: url,
            timestamp: new Date().toISOString(),
            technologies: detected
        };

        marshall.download.save(
            JSON.stringify(report, null, 2),
            `tech-report-${new URL(url).hostname}.json`,
            'application/json'
        );
        marshall.ui.notify('Report exported', 'success');
    }
}

const techDetector = new TechDetector();

marshall.extension.onActivate(async () => {
    await techDetector.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Tech Detector] Extension deactivated');
});

marshall.extension.export('detect', (data) => techDetector.detect(data));
