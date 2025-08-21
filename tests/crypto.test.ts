import { CryptoEngine } from '../src/crypto';

describe('CryptoEngine', () => {
  describe('deriveKey', () => {
    it('should derive a key using PBKDF2 for AES-256', async () => {
      const password = 'testPassword123';
      const salt = new Uint8Array(Buffer.from('saltsaltsalt'));
      const key = await CryptoEngine.deriveKey(password, salt, 'AES-256', { iterations: 1000 });

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it('should derive a key using PBKDF2 for AES-128', async () => {
      const password = 'testPassword123';
      const salt = new Uint8Array(Buffer.from('saltsaltsalt'));
      const key = await CryptoEngine.deriveKey(password, salt, 'AES-128', { iterations: 1000 });

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(16);
    });

    it('should derive a key using MD5 for RC4-128', async () => {
      const password = 'testPassword123';
      const salt = new Uint8Array(Buffer.from('saltsaltsalt'));
      const key = await CryptoEngine.deriveKey(password, salt, 'RC4-128');

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(16);
    });

    it('should produce different keys for different passwords', async () => {
      const salt = new Uint8Array(Buffer.from('saltsaltsalt'));
      const key1 = await CryptoEngine.deriveKey('password1', salt, 'AES-256');
      const key2 = await CryptoEngine.deriveKey('password2', salt, 'AES-256');

      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it('should produce different keys for different salts', async () => {
      const password = 'testPassword';
      const key1 = await CryptoEngine.deriveKey(password, new Uint8Array(Buffer.from('salt1')), 'AES-256');
      const key2 = await CryptoEngine.deriveKey(password, new Uint8Array(Buffer.from('salt2')), 'AES-256');

      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });
  });

  describe('generateSalt', () => {
    it('should generate a salt of default length', () => {
      const salt = CryptoEngine.generateSalt();
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(16);
    });

    it('should generate a salt of specified length', () => {
      const salt = CryptoEngine.generateSalt(32);
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(32);
    });

    it('should generate different salts each time', () => {
      const salt1 = CryptoEngine.generateSalt();
      const salt2 = CryptoEngine.generateSalt();
      expect(Buffer.from(salt1).equals(Buffer.from(salt2))).toBe(false);
    });
  });

  describe('AES encryption/decryption', () => {
    it('should encrypt and decrypt data with AES-256', async () => {
      const data = new Uint8Array(Buffer.from('This is secret data'));
      const key = CryptoEngine.generateSecureRandom(32);

      const { encrypted, iv } = await CryptoEngine.encryptAES(data, key, 'AES-256');
      const decrypted = await CryptoEngine.decryptAES(encrypted, key, iv, 'AES-256');

      expect(Buffer.from(decrypted).toString()).toBe(Buffer.from(data).toString());
    });

    it('should encrypt and decrypt data with AES-128', async () => {
      const data = new Uint8Array(Buffer.from('This is secret data'));
      const key = CryptoEngine.generateSecureRandom(16);

      const { encrypted, iv } = await CryptoEngine.encryptAES(data, key, 'AES-128');
      const decrypted = await CryptoEngine.decryptAES(encrypted, key, iv, 'AES-128');

      expect(Buffer.from(decrypted).toString()).toBe(Buffer.from(data).toString());
    });

    it('should produce different ciphertext for same data with different IVs', async () => {
      const data = new Uint8Array(Buffer.from('This is secret data'));
      const key = CryptoEngine.generateSecureRandom(32);

      const result1 = await CryptoEngine.encryptAES(data, key, 'AES-256');
      const result2 = await CryptoEngine.encryptAES(data, key, 'AES-256');

      expect(Buffer.from(result1.encrypted).equals(Buffer.from(result2.encrypted))).toBe(false);
      expect(Buffer.from(result1.iv).equals(Buffer.from(result2.iv))).toBe(false);
    });
  });

  describe('HMAC', () => {
    it('should generate and verify HMAC', async () => {
      const data = new Uint8Array(Buffer.from('Data to authenticate'));
      const key = new Uint8Array(Buffer.from('hmacKey123'));

      const hmac = await CryptoEngine.generateHMAC(data, key);
      const isValid = await CryptoEngine.verifyHMAC(data, key, hmac);

      expect(isValid).toBe(true);
    });

    it('should fail HMAC verification with wrong key', async () => {
      const data = new Uint8Array(Buffer.from('Data to authenticate'));
      const key1 = new Uint8Array(Buffer.from('hmacKey123'));
      const key2 = new Uint8Array(Buffer.from('wrongKey456'));

      const hmac = await CryptoEngine.generateHMAC(data, key1);
      const isValid = await CryptoEngine.verifyHMAC(data, key2, hmac);

      expect(isValid).toBe(false);
    });

    it('should fail HMAC verification with tampered data', async () => {
      const data = new Uint8Array(Buffer.from('Data to authenticate'));
      const tamperedData = new Uint8Array(Buffer.from('Tampered data'));
      const key = new Uint8Array(Buffer.from('hmacKey123'));

      const hmac = await CryptoEngine.generateHMAC(data, key);
      const isValid = await CryptoEngine.verifyHMAC(tamperedData, key, hmac);

      expect(isValid).toBe(false);
    });
  });

  describe('hashPassword', () => {
    it('should hash password consistently', async () => {
      const password = 'myPassword123';
      const hash1 = await CryptoEngine.hashPassword(password);
      const hash2 = await CryptoEngine.hashPassword(password);

      expect(Buffer.from(hash1).equals(Buffer.from(hash2))).toBe(true);
    });

    it('should produce different hashes for different passwords', async () => {
      const hash1 = await CryptoEngine.hashPassword('password1');
      const hash2 = await CryptoEngine.hashPassword('password2');

      expect(Buffer.from(hash1).equals(Buffer.from(hash2))).toBe(false);
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate random bytes of specified length', () => {
      const random = CryptoEngine.generateSecureRandom(24);
      expect(random).toBeInstanceOf(Uint8Array);
      expect(random.length).toBe(24);
    });

    it('should generate different random bytes each time', () => {
      const random1 = CryptoEngine.generateSecureRandom(16);
      const random2 = CryptoEngine.generateSecureRandom(16);
      expect(Buffer.from(random1).equals(Buffer.from(random2))).toBe(false);
    });
  });
});