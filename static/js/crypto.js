class NoteCrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
    }

    // Generate a random key for encryption
    async generateKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: this.algorithm,
                length: this.keyLength,
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // Export key to raw bytes
    async exportKey(key) {
        const exported = await window.crypto.subtle.exportKey('raw', key);
        return new Uint8Array(exported);
    }

    // Import key from raw bytes
    async importKey(keyBytes) {
        return await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: this.algorithm },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Encrypt text with a key
    async encrypt(text, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv,
            },
            key,
            data
        );

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);
        
        return result;
    }

    // Decrypt data with a key
    async decrypt(encryptedData, key) {
        const iv = encryptedData.slice(0, 12);
        const data = encryptedData.slice(12);
        
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv: iv,
            },
            key,
            data
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // Convert bytes to base64
    bytesToBase64(bytes) {
        const binString = String.fromCharCode(...bytes);
        return btoa(binString);
    }

    // Convert base64 to bytes
    base64ToBytes(base64) {
        const binString = atob(base64);
        return Uint8Array.from(binString, (char) => char.charCodeAt(0));
    }

    // Generate URL-safe key for sharing
    async generateShareableKey(key) {
        const keyBytes = await this.exportKey(key);
        return this.bytesToBase64(keyBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    // Import key from URL-safe string
    async importShareableKey(shareableKey) {
        // Add padding if needed
        const padding = '='.repeat((4 - (shareableKey.length % 4)) % 4);
        const base64 = shareableKey.replace(/-/g, '+').replace(/_/g, '/') + padding;
        const keyBytes = this.base64ToBytes(base64);
        return await this.importKey(keyBytes);
    }
}

// Global instance
window.noteCrypto = new NoteCrypto();

// Utility functions
window.showAlert = function(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        if (alertDiv && alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
};

window.copyToClipboard = async function(text) {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('Copied to clipboard!', 'success');
    } catch (err) {
        showAlert('Failed to copy to clipboard', 'warning');
    }
};

// Theme management
class ThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.init();
    }

    init() {
        this.applyTheme(this.currentTheme);
        
        // Add theme toggle listener
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.applyTheme(this.currentTheme);
        localStorage.setItem('theme', this.currentTheme);
    }

    applyTheme(theme) {
        const body = document.body;
        const themeIcon = document.getElementById('themeIcon');
        const highlightDark = document.getElementById('highlight-dark');
        const highlightLight = document.getElementById('highlight-light');
        
        if (theme === 'light') {
            body.classList.remove('bg-dark', 'text-light');
            body.classList.add('bg-light', 'text-dark');
            if (themeIcon) themeIcon.textContent = '🌞';
            
            // Switch Highlight.js themes
            if (highlightDark) highlightDark.disabled = true;
            if (highlightLight) highlightLight.disabled = false;
            
            // Update form controls
            this.updateFormControls('light');
        } else {
            body.classList.remove('bg-light', 'text-dark');
            body.classList.add('bg-dark', 'text-light');
            if (themeIcon) themeIcon.textContent = '🌙';
            
            // Switch Highlight.js themes
            if (highlightDark) highlightDark.disabled = false;
            if (highlightLight) highlightLight.disabled = true;
            
            // Update form controls
            this.updateFormControls('dark');
        }
        
        // Re-highlight any visible code blocks
        if (window.hljs) {
            setTimeout(() => {
                document.querySelectorAll('pre code').forEach((block) => {
                    hljs.highlightElement(block);
                });
            }, 50);
        }
    }

    updateFormControls(theme) {
        const formControls = document.querySelectorAll('.form-control, .form-select');
        const cards = document.querySelectorAll('.card');
        
        formControls.forEach(control => {
            if (theme === 'light') {
                control.classList.remove('bg-dark', 'text-light', 'border-secondary');
                control.classList.add('bg-white', 'text-dark', 'border-light');
            } else {
                control.classList.remove('bg-white', 'text-dark', 'border-light');
                control.classList.add('bg-dark', 'text-light', 'border-secondary');
            }
        });

        cards.forEach(card => {
            if (theme === 'light') {
                card.classList.remove('bg-secondary');
                card.classList.add('bg-white');
            } else {
                card.classList.remove('bg-white');
                card.classList.add('bg-secondary');
            }
        });
    }
}

// Initialize theme manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.themeManager = new ThemeManager();
});