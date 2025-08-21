import { createHash, randomBytes, pbkdf2Sync, createHmac, createCipheriv, createDecipheriv } from 'crypto';
import { EncryptionAlgorithm, KDFOptions } from './types';

export class CryptoEngine {
  private static readonly DEFAULT_ITERATIONS = 10000;
  private static readonly DEFAULT_SALT_LENGTH = 16;
  private static readonly AES_KEY_SIZES: Record<string, number> = {
    'AES-256': 32,
    'AES-128': 16,
  };

  static deriveKey(
    password: string,
    salt: Buffer,
    algorithm: EncryptionAlgorithm,
    options?: KDFOptions,
  ): Buffer {
    const iterations = options?.iterations || this.DEFAULT_ITERATIONS;
    const keyLength = this.AES_KEY_SIZES[algorithm] || 16;

    if (algorithm === 'RC4-128') {
      return createHash('md5').update(password).digest();
    }

    return pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
  }

  static generateSalt(length?: number): Buffer {
    return randomBytes(length || this.DEFAULT_SALT_LENGTH);
  }

  static generateIV(): Buffer {
    return randomBytes(16);
  }

  static encryptAES(
    data: Buffer,
    key: Buffer,
    algorithm: 'AES-256' | 'AES-128',
  ): { encrypted: Buffer; iv: Buffer } {
    const iv = this.generateIV();
    const cipherAlgorithm = algorithm === 'AES-256' ? 'aes-256-cbc' : 'aes-128-cbc';
    const cipher = createCipheriv(cipherAlgorithm, key, iv);
    
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    
    return { encrypted, iv };
  }

  static decryptAES(
    encryptedData: Buffer,
    key: Buffer,
    iv: Buffer,
    algorithm: 'AES-256' | 'AES-128',
  ): Buffer {
    const cipherAlgorithm = algorithm === 'AES-256' ? 'aes-256-cbc' : 'aes-128-cbc';
    const decipher = createDecipheriv(cipherAlgorithm, key, iv);
    
    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }

  static generateHMAC(data: Buffer, key: Buffer): Buffer {
    return createHmac('sha256', key).update(data).digest();
  }

  static verifyHMAC(data: Buffer, key: Buffer, hmac: Buffer): boolean {
    const calculatedHmac = this.generateHMAC(data, key);
    return calculatedHmac.equals(hmac);
  }

  static hashPassword(password: string): Buffer {
    return createHash('sha256').update(password).digest();
  }

  static generateSecureRandom(length: number): Buffer {
    return randomBytes(length);
  }
}