/**
 * Password Analyzer Extension for Marshall Browser
 * Password strength analysis and breach checking
 * Part of Marshall Extensions Collection
 */

class PasswordAnalyzer {
    constructor() {
        this.hibpUrl = 'https://api.pwnedpasswords.com/range/';
        this.commonPasswords = new Set([
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
            'password1', 'p@ssw0rd', 'passw0rd', '1234567890'
        ]);
    }

    async init() {
        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+P', () => this.showAnalyzer());

        // Register context menu for password fields
        marshall.contextMenu.register({
            id: 'analyze-password',
            title: 'Analyze Password',
            contexts: ['editable'],
            onclick: (info) => this.analyzeFromContext(info)
        });

        // Register toolbar button
        marshall.toolbar.addButton({
            id: 'password-analyzer-btn',
            icon: '🔑',
            tooltip: 'Password Analyzer',
            onclick: () => this.showAnalyzer()
        });

        console.log('[Password Analyzer] Extension initialized');
        return true;
    }

    async sha1(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    async checkBreach(password) {
        try {
            const hash = await this.sha1(password);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);

            const response = await marshall.network.fetch(this.hibpUrl + prefix);
            
            if (!response.ok) {
                throw new Error('HIBP API error');
            }

            const text = await response.text();
            const lines = text.split('\n');

            for (const line of lines) {
                const [hashSuffix, count] = line.split(':');
                if (hashSuffix.trim() === suffix) {
                    return parseInt(count.trim());
                }
            }

            return 0;
        } catch (error) {
            console.error('[Password Analyzer] Breach check error:', error);
            return -1; // Error indicator
        }
    }

    analyzeStrength(password) {
        const analysis = {
            length: password.length,
            hasLower: /[a-z]/.test(password),
            hasUpper: /[A-Z]/.test(password),
            hasDigit: /\d/.test(password),
            hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
            hasSpace: /\s/.test(password),
            isCommon: this.commonPasswords.has(password.toLowerCase()),
            hasSequential: this.hasSequential(password),
            hasRepeating: this.hasRepeating(password),
            entropy: this.calculateEntropy(password)
        };

        // Calculate score (0-100)
        let score = 0;
        
        // Length scoring
        if (analysis.length >= 8) score += 10;
        if (analysis.length >= 12) score += 10;
        if (analysis.length >= 16) score += 10;
        if (analysis.length >= 20) score += 5;

        // Character variety
        if (analysis.hasLower) score += 10;
        if (analysis.hasUpper) score += 10;
        if (analysis.hasDigit) score += 10;
        if (analysis.hasSpecial) score += 15;

        // Entropy bonus
        if (analysis.entropy > 40) score += 10;
        if (analysis.entropy > 60) score += 10;

        // Penalties
        if (analysis.isCommon) score -= 30;
        if (analysis.hasSequential) score -= 10;
        if (analysis.hasRepeating) score -= 10;
        if (analysis.length < 8) score -= 20;

        analysis.score = Math.max(0, Math.min(100, score));
        analysis.rating = this.getStrengthRating(analysis.score);

        return analysis;
    }

    hasSequential(password) {
        const sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl'];
        const lower = password.toLowerCase();
        
        for (const seq of sequences) {
            for (let i = 0; i < seq.length - 2; i++) {
                if (lower.includes(seq.substring(i, i + 3))) {
                    return true;
                }
            }
        }
        return false;
    }

    hasRepeating(password) {
        return /(.)\1{2,}/.test(password);
    }

    calculateEntropy(password) {
        let charset = 0;
        if (/[a-z]/.test(password)) charset += 26;
        if (/[A-Z]/.test(password)) charset += 26;
        if (/\d/.test(password)) charset += 10;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) charset += 32;
        if (/\s/.test(password)) charset += 1;

        return password.length * Math.log2(charset || 1);
    }

    getStrengthRating(score) {
        if (score >= 80) return { label: 'Excellent', color: '#4CAF50', icon: '💪' };
        if (score >= 60) return { label: 'Good', color: '#8BC34A', icon: '👍' };
        if (score >= 40) return { label: 'Fair', color: '#FFC107', icon: '⚠️' };
        if (score >= 20) return { label: 'Weak', color: '#FF9800', icon: '⚡' };
        return { label: 'Very Weak', color: '#f44336', icon: '💀' };
    }

    generatePassword(length = 16, options = {}) {
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        let charset = '';
        if (options.includeLower !== false) charset += lower;
        if (options.includeUpper !== false) charset += upper;
        if (options.includeDigits !== false) charset += digits;
        if (options.includeSpecial !== false) charset += special;

        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        // Ensure at least one of each required type
        const requirements = [];
        if (options.includeLower !== false && !/[a-z]/.test(password)) {
            requirements.push(lower[Math.floor(Math.random() * lower.length)]);
        }
        if (options.includeUpper !== false && !/[A-Z]/.test(password)) {
            requirements.push(upper[Math.floor(Math.random() * upper.length)]);
        }
        if (options.includeDigits !== false && !/\d/.test(password)) {
            requirements.push(digits[Math.floor(Math.random() * digits.length)]);
        }
        if (options.includeSpecial !== false && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            requirements.push(special[Math.floor(Math.random() * special.length)]);
        }

        // Replace random characters with requirements
        for (let i = 0; i < requirements.length && i < password.length; i++) {
            const pos = Math.floor(Math.random() * password.length);
            password = password.substring(0, pos) + requirements[i] + password.substring(pos + 1);
        }

        return password;
    }

    formatResult(password, analysis, breachCount) {
        const rating = analysis.rating;
        
        return `
            <div class="password-analyzer">
                <div class="password-header">
                    <h2>🔑 Password Analyzer</h2>
                </div>

                <div class="password-input-section">
                    <input type="password" id="password-input" value="${password}" 
                           placeholder="Enter password to analyze"
                           oninput="passwordAnalyzer.liveAnalyze(this.value)">
                    <button onclick="document.getElementById('password-input').type = 
                        document.getElementById('password-input').type === 'password' ? 'text' : 'password'">
                        👁️
                    </button>
                </div>

                <div class="strength-meter">
                    <div class="strength-bar" style="width: ${analysis.score}%; background: ${rating.color}"></div>
                </div>

                <div class="strength-rating" style="color: ${rating.color}">
                    <span class="rating-icon">${rating.icon}</span>
                    <span class="rating-label">${rating.label}</span>
                    <span class="rating-score">${analysis.score}/100</span>
                </div>

                ${breachCount > 0 ? `
                <div class="breach-warning">
                    <span class="breach-icon">🚨</span>
                    <span>This password has been seen <strong>${breachCount.toLocaleString()}</strong> times in data breaches!</span>
                </div>
                ` : breachCount === 0 ? `
                <div class="breach-safe">
                    <span class="breach-icon">✅</span>
                    <span>Not found in known data breaches</span>
                </div>
                ` : ''}

                <div class="analysis-details">
                    <h3>📊 Analysis</h3>
                    <table>
                        <tr>
                            <td>Length</td>
                            <td>${analysis.length} characters ${analysis.length >= 12 ? '✅' : '⚠️'}</td>
                        </tr>
                        <tr>
                            <td>Lowercase</td>
                            <td>${analysis.hasLower ? '✅ Yes' : '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>Uppercase</td>
                            <td>${analysis.hasUpper ? '✅ Yes' : '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>Numbers</td>
                            <td>${analysis.hasDigit ? '✅ Yes' : '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>Special Characters</td>
                            <td>${analysis.hasSpecial ? '✅ Yes' : '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>Entropy</td>
                            <td>${analysis.entropy.toFixed(1)} bits</td>
                        </tr>
                        <tr>
                            <td>Sequential Patterns</td>
                            <td>${analysis.hasSequential ? '⚠️ Found' : '✅ None'}</td>
                        </tr>
                        <tr>
                            <td>Repeating Characters</td>
                            <td>${analysis.hasRepeating ? '⚠️ Found' : '✅ None'}</td>
                        </tr>
                        <tr>
                            <td>Common Password</td>
                            <td>${analysis.isCommon ? '🚨 Yes' : '✅ No'}</td>
                        </tr>
                    </table>
                </div>

                <div class="password-generator">
                    <h3>🎲 Generate Strong Password</h3>
                    <div class="generator-options">
                        <label><input type="checkbox" id="gen-lower" checked> Lowercase</label>
                        <label><input type="checkbox" id="gen-upper" checked> Uppercase</label>
                        <label><input type="checkbox" id="gen-digits" checked> Numbers</label>
                        <label><input type="checkbox" id="gen-special" checked> Special</label>
                        <label>Length: <input type="number" id="gen-length" value="16" min="8" max="64"></label>
                    </div>
                    <button onclick="passwordAnalyzer.generateAndShow()" class="generate-btn">
                        🎲 Generate Password
                    </button>
                    <div id="generated-password" class="generated-password"></div>
                </div>

                <div class="password-tips">
                    <h3>💡 Tips</h3>
                    <ul>
                        <li>Use at least 12 characters</li>
                        <li>Mix uppercase, lowercase, numbers, and symbols</li>
                        <li>Avoid dictionary words and personal info</li>
                        <li>Use a unique password for each account</li>
                        <li>Consider using a password manager</li>
                    </ul>
                </div>
            </div>
        `;
    }

    async showAnalyzer(password = '') {
        marshall.ui.showPanel('<div class="password-loading">🔑 Loading analyzer...</div>');

        const analysis = this.analyzeStrength(password);
        let breachCount = -1;

        if (password) {
            const checkBreaches = await marshall.storage.get('password_check_breaches');
            if (checkBreaches !== false) {
                breachCount = await this.checkBreach(password);
            }
        }

        marshall.ui.showPanel(this.formatResult(password, analysis, breachCount), {
            title: 'Password Analyzer',
            width: 500,
            height: 700
        });
    }

    async liveAnalyze(password) {
        const analysis = this.analyzeStrength(password);
        // Update UI elements without full refresh
        document.querySelector('.strength-bar').style.width = analysis.score + '%';
        document.querySelector('.strength-bar').style.background = analysis.rating.color;
        document.querySelector('.rating-label').textContent = analysis.rating.label;
        document.querySelector('.rating-score').textContent = analysis.score + '/100';
    }

    generateAndShow() {
        const length = parseInt(document.getElementById('gen-length').value) || 16;
        const options = {
            includeLower: document.getElementById('gen-lower').checked,
            includeUpper: document.getElementById('gen-upper').checked,
            includeDigits: document.getElementById('gen-digits').checked,
            includeSpecial: document.getElementById('gen-special').checked
        };

        const password = this.generatePassword(length, options);
        const analysis = this.analyzeStrength(password);

        document.getElementById('generated-password').innerHTML = `
            <div class="generated-result">
                <code>${password}</code>
                <button onclick="navigator.clipboard.writeText('${password}'); marshall.ui.notify('Copied!', 'success')">📋 Copy</button>
            </div>
            <div class="generated-strength" style="color: ${analysis.rating.color}">
                ${analysis.rating.icon} ${analysis.rating.label} (${analysis.score}/100)
            </div>
        `;
    }

    async analyzeFromContext(info) {
        // Try to get selected text from password field
        const selection = info.selectionText || '';
        await this.showAnalyzer(selection);
    }
}

// Extension entry point
const passwordAnalyzer = new PasswordAnalyzer();

marshall.extension.onActivate(async () => {
    await passwordAnalyzer.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Password Analyzer] Extension deactivated');
});

marshall.extension.export('analyze', (pw) => passwordAnalyzer.analyzeStrength(pw));
marshall.extension.export('checkBreach', (pw) => passwordAnalyzer.checkBreach(pw));
marshall.extension.export('generate', (len, opts) => passwordAnalyzer.generatePassword(len, opts));
