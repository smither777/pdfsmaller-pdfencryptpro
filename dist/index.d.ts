export { PDFEncryptor } from './encryptor';
export { CryptoEngine } from './crypto';
export * from './types';
export declare function encryptPDF(pdfBytes: Uint8Array, userPassword: string, ownerPassword?: string, options?: {
    algorithm?: 'AES-128' | 'RC4-128';
    enableHMAC?: boolean;
    iterations?: number;
}): Promise<Uint8Array>;
//# sourceMappingURL=index.d.ts.map