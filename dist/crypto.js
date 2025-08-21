"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoEngine = void 0;
const crypto_1 = require("crypto");
class CryptoEngine {
    static DEFAULT_ITERATIONS = 10000;
    static DEFAULT_SALT_LENGTH = 16;
    static AES_KEY_SIZES = {
        'AES-256': 32,
        'AES-128': 16,
    };
    static deriveKey(password, salt, algorithm, options) {
        const iterations = options?.iterations || this.DEFAULT_ITERATIONS;
        const keyLength = this.AES_KEY_SIZES[algorithm] || 16;
        if (algorithm === 'RC4-128') {
            return (0, crypto_1.createHash)('md5').update(password).digest();
        }
        return (0, crypto_1.pbkdf2Sync)(password, salt, iterations, keyLength, 'sha256');
    }
    static generateSalt(length) {
        return (0, crypto_1.randomBytes)(length || this.DEFAULT_SALT_LENGTH);
    }
    static generateIV() {
        return (0, crypto_1.randomBytes)(16);
    }
    static encryptAES(data, key, algorithm) {
        const iv = this.generateIV();
        const cipherAlgorithm = algorithm === 'AES-256' ? 'aes-256-cbc' : 'aes-128-cbc';
        const cipher = (0, crypto_1.createCipheriv)(cipherAlgorithm, key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return { encrypted, iv };
    }
    static decryptAES(encryptedData, key, iv, algorithm) {
        const cipherAlgorithm = algorithm === 'AES-256' ? 'aes-256-cbc' : 'aes-128-cbc';
        const decipher = (0, crypto_1.createDecipheriv)(cipherAlgorithm, key, iv);
        return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    }
    static generateHMAC(data, key) {
        return (0, crypto_1.createHmac)('sha256', key).update(data).digest();
    }
    static verifyHMAC(data, key, hmac) {
        const calculatedHmac = this.generateHMAC(data, key);
        return calculatedHmac.equals(hmac);
    }
    static hashPassword(password) {
        return (0, crypto_1.createHash)('sha256').update(password).digest();
    }
    static generateSecureRandom(length) {
        return (0, crypto_1.randomBytes)(length);
    }
}
exports.CryptoEngine = CryptoEngine;
//# sourceMappingURL=crypto.js.map