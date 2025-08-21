import { EncryptionOptions, EncryptionResult } from './types';
export declare class PDFEncryptor {
    private static readonly PERMISSIONS_FLAGS;
    static encryptPDF(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<Uint8Array>;
    static encryptPDFWithMetadata(pdfBytes: Uint8Array, options: EncryptionOptions): Promise<EncryptionResult>;
    private static createEncryptionDictionary;
    private static calculatePermissions;
    private static padKey;
    private static uint8ArrayToHex;
}
//# sourceMappingURL=encryptor.d.ts.map