import { EncryptionOptions, EncryptionResult } from './types';
export declare class PDFEncryptor {
    /**
     * Encrypt a PDF with AES-256, AES-128, or RC4-128
     * Using the same approach as pdf-encrypt-lite but enhanced with AES
     */
    static encryptPDF(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<Uint8Array>;
    static encryptPDFWithMetadata(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<EncryptionResult>;
}
//# sourceMappingURL=encryptor.d.ts.map