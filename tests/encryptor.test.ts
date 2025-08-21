import { PDFEncryptor } from '../src/encryptor';
import { EncryptionOptions } from '../src/types';
import { PDFDocument } from 'pdf-lib';

describe('PDFEncryptor', () => {
  let testPdfBytes: Uint8Array;

  beforeAll(async () => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage();
    page.drawText('Test PDF Content', { x: 50, y: 500 });
    testPdfBytes = await pdfDoc.save();
  });

  describe('encryptPDF', () => {
    it('should encrypt a PDF with AES-256', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
        kdf: { iterations: 1000 },
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should encrypt a PDF with AES-128', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-128',
        kdf: { iterations: 5000 },
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should encrypt a PDF with RC4-128', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'RC4-128',
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should use default AES-256 when no algorithm specified', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should handle different user and owner passwords', async () => {
      const options: EncryptionOptions = {
        userPassword: 'userPass123',
        ownerPassword: 'ownerPass456',
        algorithm: 'AES-256',
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should enable HMAC when requested', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
        enableHMAC: true,
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should apply permission restrictions', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        permissions: {
          printing: false,
          copying: false,
          modifying: false,
        },
      };

      const encryptedBytes = await PDFEncryptor.encryptPDF(testPdfBytes, options);

      expect(encryptedBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedBytes.length).toBeGreaterThan(0);
    });

    it('should handle invalid PDF bytes', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const invalidBytes = new Uint8Array([1, 2, 3, 4]);

      await expect(PDFEncryptor.encryptPDF(invalidBytes, options)).rejects.toThrow();
    });

    it('should track encryption time with metadata', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
      };

      const result = await PDFEncryptor.encryptPDFWithMetadata(testPdfBytes, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.encryptionTime).toBeGreaterThan(0);
    });

    it('should report file size in metadata', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const result = await PDFEncryptor.encryptPDFWithMetadata(testPdfBytes, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.fileSize).toBeGreaterThan(0);
    });
  });
});