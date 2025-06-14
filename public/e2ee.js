// E2EE Configuration
const E2EE = {
    config: {
        nonceCacheFile: 'nonce_cache.json',
        trustedKeysFile: 'trusted_keys.json',
        securityLogFile: 'security.log',
        replayWindowSeconds: 31536000, // 365 days
        keyBackupDir: 'key_backups',
        saltSize: 32,
        maxMessageSize: 1024 * 1024, // 1MB
        pbkdf2Iterations: 100000,
        version: '1.0.0'
    }
};

// Security Logger
class SecurityLogger {
    constructor() {
        this.logs = [];
    }

    log(severity, message, details = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            severity,
            message,
            details
        };
        this.logs.push(logEntry);
        console.log(`[${severity}] ${message}`, details);
    }

    error(message, details = {}) {
        this.log('ERROR', message, details);
    }

    warning(message, details = {}) {
        this.log('WARNING', message, details);
    }

    info(message, details = {}) {
        this.log('INFO', message, details);
    }
}

// Input Validator
class InputValidator {
    static validateBase64(data, expectedLength = null) {
        try {
            const binary = atob(data);
            const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
            if (expectedLength && bytes.length !== expectedLength) {
                throw new Error(`Invalid length: expected ${expectedLength}, got ${bytes.length}`);
            }
            return bytes;
        } catch (e) {
            throw new Error(`Invalid base64 data: ${e.message}`);
        }
    }

    static validateMessage(message) {
        if (!message) {
            throw new Error("Message cannot be empty");
        }
        if (new TextEncoder().encode(message).length > E2EE.config.maxMessageSize) {
            throw new Error(`Message too large (max ${E2EE.config.maxMessageSize} bytes)`);
        }
    }

    static validateTimestamp(timestamp, windowSeconds = E2EE.config.replayWindowSeconds) {
        const now = Date.now();
        if (Math.abs(now - timestamp) > windowSeconds * 1000) {
            throw new Error("Message timestamp outside allowable window");
        }
    }
}

// Nonce Manager
class NonceManager {
    constructor() {
        this.nonces = new Map();
        this.logger = new SecurityLogger();
    }

    loadNonces() {
        try {
            const stored = localStorage.getItem(E2EE.config.nonceCacheFile);
            if (stored) {
                const data = JSON.parse(stored);
                this.nonces = new Map(Object.entries(data));
            }
        } catch (error) {
            this.logger.error('Failed to load nonces', { error: error.message });
        }
    }

    saveNonces() {
        try {
            const data = Object.fromEntries(this.nonces);
            localStorage.setItem(E2EE.config.nonceCacheFile, JSON.stringify(data));
        } catch (error) {
            this.logger.error('Failed to save nonces', { error: error.message });
        }
    }

    registerNonce(nonce, timestamp) {
        if (!InputValidator.validateBase64(nonce) || 
            !InputValidator.validateTimestamp(timestamp)) {
            return false;
        }

        const now = Date.now();
        const nonceTime = new Date(timestamp).getTime();
        
        if (now - nonceTime > E2EE.config.replayWindowSeconds * 1000) {
            this.logger.warning('Nonce too old', { nonce, timestamp });
            return false;
        }

        if (this.nonces.has(nonce)) {
            this.logger.warning('Duplicate nonce detected', { nonce, timestamp });
            return false;
        }

        this.nonces.set(nonce, timestamp);
        this.saveNonces();
        return true;
    }

    cleanup() {
        const now = Date.now();
        for (const [nonce, timestamp] of this.nonces) {
            if (now - new Date(timestamp).getTime() > E2EE.config.replayWindowSeconds * 1000) {
                this.nonces.delete(nonce);
            }
        }
        this.saveNonces();
    }
}

// Crypto Engine
class CryptoEngine {
    static async deriveSharedKey(ephemeralPrivate, recipientPubBytes) {
        try {
            // Import recipient public key
            const recipientPubKey = await window.crypto.subtle.importKey(
                "raw",
                recipientPubBytes,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            );

            const sharedSecret = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: recipientPubKey
                },
                ephemeralPrivate,
                256
            );

            const salt = await window.crypto.subtle.digest(
                "SHA-256",
                sharedSecret
            );

            const key = await window.crypto.subtle.importKey(
                "raw",
                sharedSecret,
                { name: "HKDF" },
                false,
                ["deriveBits"]
            );

            return await window.crypto.subtle.deriveBits(
                {
                    name: "HKDF",
                    salt,
                    info: new TextEncoder().encode("e2ee-handshake-v3"),
                    hash: "SHA-512"
                },
                key,
                256
            );
        } catch (error) {
            throw new Error(`Failed to derive shared key: ${error.message}`);
        }
    }

    static async encryptMessage(message, recipientPubB64) {
        InputValidator.validateMessage(message);
        const recipientPubBytes = InputValidator.validateBase64(recipientPubB64);

        try {
            // Generate ephemeral key pair
            const ephemeralKeyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveBits", "deriveKey"]
            );

            const sharedKey = await this.deriveSharedKey(
                ephemeralKeyPair.privateKey,
                recipientPubBytes
            );

            // Generate nonce
            const nonce = window.crypto.getRandomValues(new Uint8Array(12));
            const nonceB64 = btoa(String.fromCharCode(...nonce));

            // Encrypt message
            const messageBytes = new TextEncoder().encode(message);
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: nonce
                },
                await window.crypto.subtle.importKey(
                    "raw",
                    sharedKey,
                    { name: "AES-GCM" },
                    false,
                    ["encrypt"]
                ),
                messageBytes
            );

            return {
                ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
                nonce: nonceB64,
                ephemeralPub: btoa(String.fromCharCode(...new Uint8Array(
                    await window.crypto.subtle.exportKey(
                        "raw",
                        ephemeralKeyPair.publicKey
                    )
                ))),
                timestamp: Date.now()
            };
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    static async decryptMessage(data, recipientPrivateKey) {
        try {
            const ciphertext = InputValidator.validateBase64(data.ciphertext);
            const nonce = InputValidator.validateBase64(data.nonce);
            const ephemeralPub = InputValidator.validateBase64(data.ephemeralPub);

            InputValidator.validateTimestamp(data.timestamp);

            const sharedKey = await this.deriveSharedKey(
                recipientPrivateKey,
                ephemeralPub
            );

            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: nonce
                },
                await window.crypto.subtle.importKey(
                    "raw",
                    sharedKey,
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                ),
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }
}

// E2EE Messenger
class E2EEMessenger {
    constructor() {
        this.nonceManager = new NonceManager();
        this.logger = new SecurityLogger();
        this.keyPair = null;
    }

    async initialize() {
        try {
            // Attempt to load keys from localStorage
            const storedPriv = localStorage.getItem('e2ee_priv'); // pkcs8 base64
            const storedPub = localStorage.getItem('e2ee_pub');  // raw   base64

            let loaded = false;
            if (storedPriv && storedPub) {
                try {
                    // Import existing keys (private = pkcs8, public = raw)
                    const privBytes = InputValidator.validateBase64(storedPriv);
                    const pubBytes  = InputValidator.validateBase64(storedPub);

                    const privKey = await window.crypto.subtle.importKey(
                        "pkcs8",
                        privBytes.buffer,
                        { name: "ECDH", namedCurve: "P-256" },
                        true,
                        ["deriveBits", "deriveKey"]
                    );

                    const pubKey = await window.crypto.subtle.importKey(
                        "raw",
                        pubBytes.buffer,
                        { name: "ECDH", namedCurve: "P-256" },
                        true,
                        []
                    );

                    this.keyPair = { privateKey: privKey, publicKey: pubKey };
                    this.logger.info('E2EE key pair loaded from storage');
                    loaded = true;
                } catch (e) {
                    console.warn('Failed to import stored E2EE keys, generating new pair.', e);
                    localStorage.removeItem('e2ee_priv');
                    localStorage.removeItem('e2ee_pub');
                }
            }

            if (!loaded) {
                // Generate new key pair and persist (private as pkcs8, public as raw)
                this.keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256"
                    },
                    true,
                    ["deriveBits", "deriveKey"]
                );

                const exportedPriv = new Uint8Array(await window.crypto.subtle.exportKey("pkcs8", this.keyPair.privateKey));
                const exportedPub  = new Uint8Array(await window.crypto.subtle.exportKey("raw",   this.keyPair.publicKey));

                localStorage.setItem('e2ee_priv', btoa(String.fromCharCode(...exportedPriv)));
                localStorage.setItem('e2ee_pub',  btoa(String.fromCharCode(...exportedPub)));

                this.logger.info('E2EE key pair generated and stored');
            }

            this.nonceManager.loadNonces();
            this.logger.info('E2EE system initialized');
        } catch (error) {
            this.logger.error('Failed to initialize E2EE system', { error: error.message });
            throw error;
        }
    }

    async getPublicKey() {
        if (!this.keyPair) {
            throw new Error('E2EE system not initialized');
        }

        const exported = await window.crypto.subtle.exportKey(
            "raw",
            this.keyPair.publicKey
        );
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    async encryptMessage(message, recipientPubB64) {
        if (!this.keyPair) {
            throw new Error('E2EE system not initialized');
        }

        return await CryptoEngine.encryptMessage(message, recipientPubB64);
    }

    async decryptMessage(data) {
        if (!this.keyPair) {
            throw new Error('E2EE system not initialized');
        }

        return await CryptoEngine.decryptMessage(data, this.keyPair.privateKey);
    }
}

// Export the E2EE system
window.E2EE = E2EE;u8
window.E2EEMessenger = E2EEMessenger; 
