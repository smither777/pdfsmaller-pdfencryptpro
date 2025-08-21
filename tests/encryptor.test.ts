import { PDFEncryptor } from '../src/encryptor';
import { EncryptionOptions } from '../src/types';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { join } from 'path';
import { PDFDocument } from 'pdf-lib';

describe('PDFEncryptor', () => {
  const testDir = join(__dirname, 'fixtures');
  const testPdfPath = join(testDir, 'test.pdf');
  const outputPath = join(testDir, 'test_encrypted.pdf');

  beforeAll(async () => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage();
    page.drawText('Test PDF Content', { x: 50, y: 500 });
    const pdfBytes = await pdfDoc.save();
    writeFileSync(testPdfPath, pdfBytes);
  });

  afterAll(() => {
    if (existsSync(testPdfPath)) unlinkSync(testPdfPath);
    if (existsSync(outputPath)) unlinkSync(outputPath);
  });

  afterEach(() => {
    if (existsSync(outputPath)) unlinkSync(outputPath);
  });

  describe('encryptPDF', () => {
    it('should encrypt a PDF with AES-256', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
        kdf: { iterations: 1000 },
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.outputPath).toBe(outputPath);
      expect(existsSync(outputPath)).toBe(true);
      expect(result.metadata?.algorithm).toBe('AES-256');
      expect(result.metadata?.kdfIterations).toBe(1000);
    });

    it('should encrypt a PDF with AES-128', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-128',
        kdf: { iterations: 5000 },
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.algorithm).toBe('AES-128');
      expect(result.metadata?.kdfIterations).toBe(5000);
    });

    it('should encrypt a PDF with RC4-128', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'RC4-128',
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.algorithm).toBe('RC4-128');
    });

    it('should use default AES-256 when no algorithm specified', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.algorithm).toBe('AES-256');
    });

    it('should handle different user and owner passwords', async () => {
      const options: EncryptionOptions = {
        userPassword: 'userPass123',
        ownerPassword: 'ownerPass456',
        algorithm: 'AES-256',
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(existsSync(outputPath)).toBe(true);
    });

    it('should enable HMAC when requested', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
        enableHMAC: true,
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.hmacEnabled).toBe(true);
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

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(existsSync(outputPath)).toBe(true);
    });

    it('should return error for non-existent input file', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const result = await PDFEncryptor.encryptPDF(
        'non-existent-file.pdf',
        outputPath,
        options,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Input file not found');
    });

    it('should track encryption time', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
        algorithm: 'AES-256',
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.encryptionTime).toBeGreaterThan(0);
    });

    it('should report file size in metadata', async () => {
      const options: EncryptionOptions = {
        userPassword: 'testPassword123',
      };

      const result = await PDFEncryptor.encryptPDF(testPdfPath, outputPath, options);

      expect(result.success).toBe(true);
      expect(result.metadata?.fileSize).toBeGreaterThan(0);
    });
  });

  describe('generateOutputPath', () => {
    it('should generate output path with default suffix', () => {
      const input = '/path/to/document.pdf';
      const output = PDFEncryptor.generateOutputPath(input);
      expect(output).toBe('/path/to/document_encrypted.pdf');
    });

    it('should generate output path with custom suffix', () => {
      const input = '/path/to/document.pdf';
      const output = PDFEncryptor.generateOutputPath(input, '_secure');
      expect(output).toBe('/path/to/document_secure.pdf');
    });

    it('should handle files without extension properly', () => {
      const input = '/path/to/document';
      const output = PDFEncryptor.generateOutputPath(input);
      expect(output).toBe('/path/to/document_encrypted.pdf');
    });
  });
});