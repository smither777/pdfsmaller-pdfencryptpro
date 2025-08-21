import { encryptPDFWithAES } from './pdf-encrypt-aes';
import {
  EncryptionOptions,
  EncryptionResult,
  EncryptionMetadata,
} from './types';

export class PDFEncryptor {
  /**
   * Encrypt a PDF with AES-256, AES-128, or RC4-128
   * Using the same approach as pdf-encrypt-lite but enhanced with AES
   */
  static async encryptPDF(
    pdfBytes: Uint8Array,
    options: EncryptionOptions,
  ): Promise<Uint8Array> {
    // Use our AES encryption implementation
    return await encryptPDFWithAES(pdfBytes, options);
  }

  static async encryptPDFWithMetadata(
    pdfBytes: Uint8Array,
    options: EncryptionOptions,
  ): Promise<EncryptionResult> {
    const startTime = Date.now();

    try {
      const encryptedBytes = await this.encryptPDF(pdfBytes, options);

      const metadata: EncryptionMetadata = {
        algorithm: options.algorithm || 'AES-256',
        kdfIterations: options.kdf?.iterations || 10000,
        hmacEnabled: options.enableHMAC || false,
        fileSize: encryptedBytes.length,
        encryptionTime: Date.now() - startTime,
      };

      return {
        success: true,
        encryptedBytes,
        metadata,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }
}