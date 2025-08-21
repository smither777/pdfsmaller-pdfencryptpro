"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PDFEncryptor = void 0;
const pdf_encrypt_aes_1 = require("./pdf-encrypt-aes");
class PDFEncryptor {
    /**
     * Encrypt a PDF with AES-256, AES-128, or RC4-128
     * Using the same approach as pdf-encrypt-lite but enhanced with AES
     */
    static async encryptPDF(pdfBytes, options) {
        // Use our AES encryption implementation
        return await (0, pdf_encrypt_aes_1.encryptPDFWithAES)(pdfBytes, options);
    }
    static async encryptPDFWithMetadata(pdfBytes, options) {
        const startTime = Date.now();
        try {
            const encryptedBytes = await this.encryptPDF(pdfBytes, options);
            const metadata = {
                algorithm: options.algorithm || 'AES-128',
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
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
            };
        }
    }
}
exports.PDFEncryptor = PDFEncryptor;
//# sourceMappingURL=encryptor.js.map