import { PDFDocument, PDFDict, PDFName, PDFHexString, PDFNumber } from 'pdf-lib';
import { CryptoEngine } from './crypto';
import {
  EncryptionOptions,
  EncryptionResult,
  EncryptionMetadata,
  Permissions,
  EncryptionAlgorithm,
} from './types';

export class PDFEncryptor {
  private static readonly PERMISSIONS_FLAGS = {
    printing: 0x00000004,
    modifying: 0x00000008,
    copying: 0x00000010,
    annotating: 0x00000020,
    fillingForms: 0x00000100,
    contentAccessibility: 0x00000200,
    documentAssembly: 0x00000400,
    highQualityPrinting: 0x00000800,
  };

  static async encryptPDF(
    pdfBytes: Uint8Array,
    options: EncryptionOptions,
  ): Promise<Uint8Array> {

    const pdfDoc = await PDFDocument.load(pdfBytes);

    const algorithm = options.algorithm || 'AES-256';
    const userPassword = options.userPassword;
    const ownerPassword = options.ownerPassword || userPassword;

    const salt = CryptoEngine.generateSalt();
    const userKey = await CryptoEngine.deriveKey(userPassword, salt, algorithm, options.kdf);
    const ownerKey = await CryptoEngine.deriveKey(ownerPassword, salt, algorithm, options.kdf);

    const permissions = this.calculatePermissions(options.permissions);

    const encryptDict = await this.createEncryptionDictionary(
      pdfDoc,
      algorithm,
      userKey,
      ownerKey,
      salt,
      permissions,
      options,
    );

    pdfDoc.context.trailerInfo.Encrypt = pdfDoc.context.register(encryptDict);

    if (options.enableHMAC) {
      const documentId = pdfDoc.context.trailerInfo.ID;
      if (documentId && Array.isArray(documentId)) {
        const hmacKey = await CryptoEngine.deriveKey(
          userPassword + ownerPassword,
          salt,
          algorithm,
          options.kdf,
        );
        const documentBytes = await pdfDoc.save();
        const hmac = await CryptoEngine.generateHMAC(new Uint8Array(documentBytes), hmacKey);
        
        encryptDict.set(PDFName.of('HMAC'), PDFHexString.of(this.uint8ArrayToHex(hmac)));
      }
    }

    const encryptedBytes = await pdfDoc.save({
      useObjectStreams: false,
    });

    return new Uint8Array(encryptedBytes);
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

  private static async createEncryptionDictionary(
    pdfDoc: PDFDocument,
    algorithm: EncryptionAlgorithm,
    userKey: Uint8Array,
    ownerKey: Uint8Array,
    salt: Uint8Array,
    permissions: number,
    options: EncryptionOptions,
  ): Promise<PDFDict> {
    const encryptDict = pdfDoc.context.obj({});

    encryptDict.set(PDFName.of('Filter'), PDFName.of('Standard'));

    if (algorithm === 'RC4-128') {
      encryptDict.set(PDFName.of('V'), PDFNumber.of(2));
      encryptDict.set(PDFName.of('R'), PDFNumber.of(3));
      encryptDict.set(PDFName.of('Length'), PDFNumber.of(128));
    } else {
      encryptDict.set(PDFName.of('V'), PDFNumber.of(5));
      encryptDict.set(PDFName.of('R'), PDFNumber.of(6));
      encryptDict.set(PDFName.of('Length'), PDFNumber.of(algorithm === 'AES-256' ? 256 : 128));

      const cfDict = pdfDoc.context.obj({});
      const stdCFDict = pdfDoc.context.obj({});
      
      stdCFDict.set(PDFName.of('CFM'), PDFName.of('AESV3'));
      stdCFDict.set(
        PDFName.of('AuthEvent'),
        PDFName.of(options.ownerPassword ? 'DocOpen' : 'EFOpen'),
      );
      stdCFDict.set(PDFName.of('Length'), PDFNumber.of(algorithm === 'AES-256' ? 32 : 16));

      cfDict.set(PDFName.of('StdCF'), stdCFDict);
      encryptDict.set(PDFName.of('CF'), cfDict);
      encryptDict.set(PDFName.of('StmF'), PDFName.of('StdCF'));
      encryptDict.set(PDFName.of('StrF'), PDFName.of('StdCF'));
    }

    const userKeyHex = this.uint8ArrayToHex(this.padKey(userKey, 32));
    const ownerKeyHex = this.uint8ArrayToHex(this.padKey(ownerKey, 32));

    encryptDict.set(PDFName.of('U'), PDFHexString.of(userKeyHex));
    encryptDict.set(PDFName.of('O'), PDFHexString.of(ownerKeyHex));
    encryptDict.set(PDFName.of('P'), PDFNumber.of(permissions));

    if (algorithm !== 'RC4-128' && options.kdf) {
      encryptDict.set(PDFName.of('Salt'), PDFHexString.of(this.uint8ArrayToHex(salt)));
      encryptDict.set(
        PDFName.of('Iterations'),
        PDFNumber.of(options.kdf.iterations || 10000),
      );
    }

    return encryptDict;
  }

  private static calculatePermissions(permissions?: Permissions): number {
    let flags = 0xfffff0c0;

    if (permissions) {
      if (permissions.printing) flags |= this.PERMISSIONS_FLAGS.printing;
      if (permissions.modifying) flags |= this.PERMISSIONS_FLAGS.modifying;
      if (permissions.copying) flags |= this.PERMISSIONS_FLAGS.copying;
      if (permissions.annotating) flags |= this.PERMISSIONS_FLAGS.annotating;
      if (permissions.fillingForms) flags |= this.PERMISSIONS_FLAGS.fillingForms;
      if (permissions.contentAccessibility) flags |= this.PERMISSIONS_FLAGS.contentAccessibility;
      if (permissions.documentAssembly) flags |= this.PERMISSIONS_FLAGS.documentAssembly;
      if (permissions.highQualityPrinting) flags |= this.PERMISSIONS_FLAGS.highQualityPrinting;
    }

    return flags;
  }

  private static padKey(key: Uint8Array, length: number): Uint8Array {
    if (key.length >= length) return key.slice(0, length);
    
    const padded = new Uint8Array(length);
    padded.set(key);
    return padded;
  }

  private static uint8ArrayToHex(array: Uint8Array): string {
    return Array.from(array)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }
}