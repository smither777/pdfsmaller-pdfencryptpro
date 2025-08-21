import { EncryptionOptions } from './types';
/**
 * Implements AES-256 encryption for PDF according to PDF 2.0 specification
 * Works in edge environments using Web Crypto API
 */
export declare class PDFAESEncryptor {
    /**
     * Encrypt a PDF with AES-256
     */
    static encryptPDF(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<Uint8Array>;
    /**
     * Apply AES encryption to the PDF document
     */
    private static applyAESEncryption;
    /**
     * Generate encryption keys according to PDF spec
     */
    private static generateKeys;
    /**
     * Create the encryption dictionary
     */
    private static createEncryptionDict;
    /**
     * Encrypt all streams in the document
     */
    private static encryptAllStreams;
    /**
     * Build user key string
     */
    private static buildUserKey;
    /**
     * Build owner key string
     */
    private static buildOwnerKey;
    /**
     * Calculate permission flags
     */
    private static calculatePermissions;
    /**
     * Convert permissions for pdf-lib
     */
    private static convertPermissions;
    /**
     * Convert bytes to hex string
     */
    private static bytesToHex;
}
//# sourceMappingURL=pdf-aes-encryptor.d.ts.map