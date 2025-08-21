import { EncryptionAlgorithm, KDFOptions } from './types';
export declare class CryptoEngine {
    private static readonly DEFAULT_ITERATIONS;
    private static readonly DEFAULT_SALT_LENGTH;
    private static readonly AES_KEY_SIZES;
    private static encoder;
    static deriveKey(password: string, salt: Uint8Array, algorithm: EncryptionAlgorithm, options?: KDFOptions): Promise<Uint8Array>;
    static pbkdf2(password: string, salt: Uint8Array, iterations: number, keyLength: number): Promise<Uint8Array>;
    private static pbkdf2Fallback;
    static generateSalt(length?: number): Uint8Array;
    static generateIV(): Uint8Array;
    static encryptAES(data: Uint8Array, key: Uint8Array, _algorithm: 'AES-256' | 'AES-128'): Promise<{
        encrypted: Uint8Array;
        iv: Uint8Array;
    }>;
    static decryptAES(encryptedData: Uint8Array, key: Uint8Array, iv: Uint8Array, _algorithm: 'AES-256' | 'AES-128'): Promise<Uint8Array>;
    static generateHMAC(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
    static verifyHMAC(data: Uint8Array, key: Uint8Array, hmac: Uint8Array): Promise<boolean>;
    static hashPassword(password: string): Promise<Uint8Array>;
    static generateSecureRandom(length: number): Uint8Array;
    private static sha256;
    private static sha256Fallback;
    private static hmacSha256;
    private static md5;
    private static concat;
}
//# sourceMappingURL=crypto.d.ts.map