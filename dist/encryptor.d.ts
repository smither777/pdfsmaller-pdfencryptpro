import { EncryptionOptions, EncryptionResult } from './types';
export declare class PDFEncryptor {
    private static readonly PERMISSIONS_FLAGS;
    static encryptPDF(inputPath: string, outputPath: string, options: EncryptionOptions): Promise<EncryptionResult>;
    private static createEncryptionDictionary;
    private static calculatePermissions;
    private static padKey;
    static generateOutputPath(inputPath: string, suffix?: string): string;
}
//# sourceMappingURL=encryptor.d.ts.map