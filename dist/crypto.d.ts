import { EncryptionAlgorithm, KDFOptions } from './types';
export declare class CryptoEngine {
    private static readonly DEFAULT_ITERATIONS;
    private static readonly DEFAULT_SALT_LENGTH;
    private static readonly AES_KEY_SIZES;
    static deriveKey(password: string, salt: Buffer, algorithm: EncryptionAlgorithm, options?: KDFOptions): Buffer;
    static generateSalt(length?: number): Buffer;
    static generateIV(): Buffer;
    static encryptAES(data: Buffer, key: Buffer, algorithm: 'AES-256' | 'AES-128'): {
        encrypted: Buffer;
        iv: Buffer;
    };
    static decryptAES(encryptedData: Buffer, key: Buffer, iv: Buffer, algorithm: 'AES-256' | 'AES-128'): Buffer;
    static generateHMAC(data: Buffer, key: Buffer): Buffer;
    static verifyHMAC(data: Buffer, key: Buffer, hmac: Buffer): boolean;
    static hashPassword(password: string): Buffer;
    static generateSecureRandom(length: number): Buffer;
}
//# sourceMappingURL=crypto.d.ts.map