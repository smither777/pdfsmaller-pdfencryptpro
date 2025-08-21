import { CryptoEngine } from '../src/crypto';

describe('CryptoEngine', () => {
  describe('deriveKey', () => {
    it('should derive a key using PBKDF2 for AES-256', () => {
      const password = 'testPassword123';
      const salt = Buffer.from('saltsaltsalt');
      const key = CryptoEngine.deriveKey(password, salt, 'AES-256', { iterations: 1000 });

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });

    it('should derive a key using PBKDF2 for AES-128', () => {
      const password = 'testPassword123';
      const salt = Buffer.from('saltsaltsalt');
      const key = CryptoEngine.deriveKey(password, salt, 'AES-128', { iterations: 1000 });

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(16);
    });

    it('should derive a key using MD5 for RC4-128', () => {
      const password = 'testPassword123';
      const salt = Buffer.from('saltsaltsalt');
      const key = CryptoEngine.deriveKey(password, salt, 'RC4-128');

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(16);
    });

    it('should produce different keys for different passwords', () => {
      const salt = Buffer.from('saltsaltsalt');
      const key1 = CryptoEngine.deriveKey('password1', salt, 'AES-256');
      const key2 = CryptoEngine.deriveKey('password2', salt, 'AES-256');

      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce different keys for different salts', () => {
      const password = 'testPassword';
      const key1 = CryptoEngine.deriveKey(password, Buffer.from('salt1'), 'AES-256');
      const key2 = CryptoEngine.deriveKey(password, Buffer.from('salt2'), 'AES-256');

      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('generateSalt', () => {
    it('should generate a salt of default length', () => {
      const salt = CryptoEngine.generateSalt();
      expect(salt).toBeInstanceOf(Buffer);
      expect(salt.length).toBe(16);
    });

    it('should generate a salt of specified length', () => {
      const salt = CryptoEngine.generateSalt(32);
      expect(salt).toBeInstanceOf(Buffer);
      expect(salt.length).toBe(32);
    });

    it('should generate different salts each time', () => {
      const salt1 = CryptoEngine.generateSalt();
      const salt2 = CryptoEngine.generateSalt();
      expect(salt1.equals(salt2)).toBe(false);
    });
  });

  describe('AES encryption/decryption', () => {
    it('should encrypt and decrypt data with AES-256', () => {
      const data = Buffer.from('This is secret data');
      const key = CryptoEngine.generateSecureRandom(32);

      const { encrypted, iv } = CryptoEngine.encryptAES(data, key, 'AES-256');
      const decrypted = CryptoEngine.decryptAES(encrypted, key, iv, 'AES-256');

      expect(decrypted.toString()).toBe(data.toString());
    });

    it('should encrypt and decrypt data with AES-128', () => {
      const data = Buffer.from('This is secret data');
      const key = CryptoEngine.generateSecureRandom(16);

      const { encrypted, iv } = CryptoEngine.encryptAES(data, key, 'AES-128');
      const decrypted = CryptoEngine.decryptAES(encrypted, key, iv, 'AES-128');

      expect(decrypted.toString()).toBe(data.toString());
    });

    it('should produce different ciphertext for same data with different IVs', () => {
      const data = Buffer.from('This is secret data');
      const key = CryptoEngine.generateSecureRandom(32);

      const result1 = CryptoEngine.encryptAES(data, key, 'AES-256');
      const result2 = CryptoEngine.encryptAES(data, key, 'AES-256');

      expect(result1.encrypted.equals(result2.encrypted)).toBe(false);
      expect(result1.iv.equals(result2.iv)).toBe(false);
    });
  });

  describe('HMAC', () => {
    it('should generate and verify HMAC', () => {
      const data = Buffer.from('Data to authenticate');
      const key = Buffer.from('hmacKey123');

      const hmac = CryptoEngine.generateHMAC(data, key);
      const isValid = CryptoEngine.verifyHMAC(data, key, hmac);

      expect(isValid).toBe(true);
    });

    it('should fail HMAC verification with wrong key', () => {
      const data = Buffer.from('Data to authenticate');
      const key1 = Buffer.from('hmacKey123');
      const key2 = Buffer.from('wrongKey456');

      const hmac = CryptoEngine.generateHMAC(data, key1);
      const isValid = CryptoEngine.verifyHMAC(data, key2, hmac);

      expect(isValid).toBe(false);
    });

    it('should fail HMAC verification with tampered data', () => {
      const data = Buffer.from('Data to authenticate');
      const tamperedData = Buffer.from('Tampered data');
      const key = Buffer.from('hmacKey123');

      const hmac = CryptoEngine.generateHMAC(data, key);
      const isValid = CryptoEngine.verifyHMAC(tamperedData, key, hmac);

      expect(isValid).toBe(false);
    });
  });

  describe('hashPassword', () => {
    it('should hash password consistently', () => {
      const password = 'myPassword123';
      const hash1 = CryptoEngine.hashPassword(password);
      const hash2 = CryptoEngine.hashPassword(password);

      expect(hash1.equals(hash2)).toBe(true);
    });

    it('should produce different hashes for different passwords', () => {
      const hash1 = CryptoEngine.hashPassword('password1');
      const hash2 = CryptoEngine.hashPassword('password2');

      expect(hash1.equals(hash2)).toBe(false);
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate random bytes of specified length', () => {
      const random = CryptoEngine.generateSecureRandom(24);
      expect(random).toBeInstanceOf(Buffer);
      expect(random.length).toBe(24);
    });

    it('should generate different random bytes each time', () => {
      const random1 = CryptoEngine.generateSecureRandom(16);
      const random2 = CryptoEngine.generateSecureRandom(16);
      expect(random1.equals(random2)).toBe(false);
    });
  });
});