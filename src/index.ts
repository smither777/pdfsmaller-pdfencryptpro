export { PDFEncryptor } from './encryptor';
export { CryptoEngine } from './crypto';
export * from './types';

// Edge-compatible convenience function
export async function encryptPDF(
  pdfBytes: Uint8Array,
  userPassword: string,
  ownerPassword?: string,
  options?: {
    algorithm?: 'AES-256' | 'AES-128' | 'RC4-128';
    enableHMAC?: boolean;
    iterations?: number;
  }
): Promise<Uint8Array> {
  const { PDFEncryptor } = await import('./encryptor');
  
  return PDFEncryptor.encryptPDF(pdfBytes, {
    userPassword,
    ownerPassword,
    algorithm: options?.algorithm || 'AES-256',
    enableHMAC: options?.enableHMAC,
    kdf: options?.iterations ? { iterations: options.iterations } : undefined,
  });
}