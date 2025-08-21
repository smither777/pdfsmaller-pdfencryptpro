import { PDFDocument, PDFDict, PDFName, PDFHexString, PDFNumber } from 'pdf-lib';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { basename, dirname, join } from 'path';
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
    inputPath: string,
    outputPath: string,
    options: EncryptionOptions,
  ): Promise<EncryptionResult> {
    const startTime = Date.now();

    try {
      if (!existsSync(inputPath)) {
        return {
          success: false,
          error: `Input file not found: ${inputPath}`,
        };
      }

      const pdfBytes = readFileSync(inputPath);
      const pdfDoc = await PDFDocument.load(pdfBytes);

      const algorithm = options.algorithm || 'AES-256';
      const userPassword = options.userPassword;
      const ownerPassword = options.ownerPassword || userPassword;

      const salt = CryptoEngine.generateSalt();
      const userKey = CryptoEngine.deriveKey(userPassword, salt, algorithm, options.kdf);
      const ownerKey = CryptoEngine.deriveKey(ownerPassword, salt, algorithm, options.kdf);

      const permissions = this.calculatePermissions(options.permissions);

      const encryptDict = this.createEncryptionDictionary(
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
          const hmacKey = CryptoEngine.deriveKey(
            userPassword + ownerPassword,
            salt,
            algorithm,
            options.kdf,
          );
          const documentBytes = await pdfDoc.save();
          const hmac = CryptoEngine.generateHMAC(Buffer.from(documentBytes), hmacKey);
          
          encryptDict.set(PDFName.of('HMAC'), PDFHexString.of(hmac.toString('hex')));
        }
      }

      const encryptedBytes = await pdfDoc.save({
        useObjectStreams: false,
      });

      writeFileSync(outputPath, encryptedBytes);

      const metadata: EncryptionMetadata = {
        algorithm,
        kdfIterations: options.kdf?.iterations || 10000,
        hmacEnabled: options.enableHMAC || false,
        fileSize: encryptedBytes.length,
        encryptionTime: Date.now() - startTime,
      };

      return {
        success: true,
        outputPath,
        metadata,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }

  private static createEncryptionDictionary(
    pdfDoc: PDFDocument,
    algorithm: EncryptionAlgorithm,
    userKey: Buffer,
    ownerKey: Buffer,
    salt: Buffer,
    permissions: number,
    options: EncryptionOptions,
  ): PDFDict {
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

    const userKeyHex = this.padKey(userKey, 32).toString('hex');
    const ownerKeyHex = this.padKey(ownerKey, 32).toString('hex');

    encryptDict.set(PDFName.of('U'), PDFHexString.of(userKeyHex));
    encryptDict.set(PDFName.of('O'), PDFHexString.of(ownerKeyHex));
    encryptDict.set(PDFName.of('P'), PDFNumber.of(permissions));

    if (algorithm !== 'RC4-128' && options.kdf) {
      encryptDict.set(PDFName.of('Salt'), PDFHexString.of(salt.toString('hex')));
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

  private static padKey(key: Buffer, length: number): Buffer {
    if (key.length >= length) return key.subarray(0, length);
    
    const padded = Buffer.alloc(length);
    key.copy(padded);
    return padded;
  }

  static generateOutputPath(inputPath: string, suffix = '_encrypted'): string {
    const dir = dirname(inputPath);
    const base = basename(inputPath, '.pdf');
    return join(dir, `${base}${suffix}.pdf`);
  }
}