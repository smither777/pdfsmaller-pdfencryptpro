/**
 * AES-256 PDF Encryption Implementation
 * Based on the successful approach from pdf-encrypt-lite
 * Enhanced with AES-256, PBKDF2, and HMAC
 */
import { EncryptionOptions } from './types';
/**
 * Main function to encrypt a PDF with AES-256
 */
export declare function encryptPDFWithAES(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<Uint8Array>;
//# sourceMappingURL=pdf-encrypt-aes.d.ts.map