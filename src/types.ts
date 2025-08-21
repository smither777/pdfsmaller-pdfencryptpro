export type EncryptionAlgorithm = 'AES-128' | 'RC4-128';

export interface EncryptionOptions {
  userPassword: string;
  ownerPassword?: string;
  algorithm?: EncryptionAlgorithm;
  permissions?: Permissions;
  kdf?: KDFOptions;
  enableHMAC?: boolean;
}

export interface KDFOptions {
  iterations?: number;
  saltLength?: number;
}

export interface Permissions {
  printing?: boolean;
  modifying?: boolean;
  copying?: boolean;
  annotating?: boolean;
  fillingForms?: boolean;
  contentAccessibility?: boolean;
  documentAssembly?: boolean;
  highQualityPrinting?: boolean;
}

export interface EncryptionResult {
  success: boolean;
  outputPath?: string;
  encryptedBytes?: Uint8Array;
  error?: string;
  metadata?: EncryptionMetadata;
}

export interface EncryptionMetadata {
  algorithm: EncryptionAlgorithm;
  kdfIterations?: number;
  hmacEnabled?: boolean;
  fileSize?: number;
  encryptionTime?: number;
}