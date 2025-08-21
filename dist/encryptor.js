"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PDFEncryptor = void 0;
const pdf_lib_1 = require("pdf-lib");
const fs_1 = require("fs");
const path_1 = require("path");
const crypto_1 = require("./crypto");
class PDFEncryptor {
    static PERMISSIONS_FLAGS = {
        printing: 0x00000004,
        modifying: 0x00000008,
        copying: 0x00000010,
        annotating: 0x00000020,
        fillingForms: 0x00000100,
        contentAccessibility: 0x00000200,
        documentAssembly: 0x00000400,
        highQualityPrinting: 0x00000800,
    };
    static async encryptPDF(inputPath, outputPath, options) {
        const startTime = Date.now();
        try {
            if (!(0, fs_1.existsSync)(inputPath)) {
                return {
                    success: false,
                    error: `Input file not found: ${inputPath}`,
                };
            }
            const pdfBytes = (0, fs_1.readFileSync)(inputPath);
            const pdfDoc = await pdf_lib_1.PDFDocument.load(pdfBytes);
            const algorithm = options.algorithm || 'AES-256';
            const userPassword = options.userPassword;
            const ownerPassword = options.ownerPassword || userPassword;
            const salt = crypto_1.CryptoEngine.generateSalt();
            const userKey = crypto_1.CryptoEngine.deriveKey(userPassword, salt, algorithm, options.kdf);
            const ownerKey = crypto_1.CryptoEngine.deriveKey(ownerPassword, salt, algorithm, options.kdf);
            const permissions = this.calculatePermissions(options.permissions);
            const encryptDict = this.createEncryptionDictionary(pdfDoc, algorithm, userKey, ownerKey, salt, permissions, options);
            pdfDoc.context.trailerInfo.Encrypt = pdfDoc.context.register(encryptDict);
            if (options.enableHMAC) {
                const documentId = pdfDoc.context.trailerInfo.ID;
                if (documentId && Array.isArray(documentId)) {
                    const hmacKey = crypto_1.CryptoEngine.deriveKey(userPassword + ownerPassword, salt, algorithm, options.kdf);
                    const documentBytes = await pdfDoc.save();
                    const hmac = crypto_1.CryptoEngine.generateHMAC(Buffer.from(documentBytes), hmacKey);
                    encryptDict.set(pdf_lib_1.PDFName.of('HMAC'), pdf_lib_1.PDFHexString.of(hmac.toString('hex')));
                }
            }
            const encryptedBytes = await pdfDoc.save({
                useObjectStreams: false,
            });
            (0, fs_1.writeFileSync)(outputPath, encryptedBytes);
            const metadata = {
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
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
            };
        }
    }
    static createEncryptionDictionary(pdfDoc, algorithm, userKey, ownerKey, salt, permissions, options) {
        const encryptDict = pdfDoc.context.obj({});
        encryptDict.set(pdf_lib_1.PDFName.of('Filter'), pdf_lib_1.PDFName.of('Standard'));
        if (algorithm === 'RC4-128') {
            encryptDict.set(pdf_lib_1.PDFName.of('V'), pdf_lib_1.PDFNumber.of(2));
            encryptDict.set(pdf_lib_1.PDFName.of('R'), pdf_lib_1.PDFNumber.of(3));
            encryptDict.set(pdf_lib_1.PDFName.of('Length'), pdf_lib_1.PDFNumber.of(128));
        }
        else {
            encryptDict.set(pdf_lib_1.PDFName.of('V'), pdf_lib_1.PDFNumber.of(5));
            encryptDict.set(pdf_lib_1.PDFName.of('R'), pdf_lib_1.PDFNumber.of(6));
            encryptDict.set(pdf_lib_1.PDFName.of('Length'), pdf_lib_1.PDFNumber.of(algorithm === 'AES-256' ? 256 : 128));
            const cfDict = pdfDoc.context.obj({});
            const stdCFDict = pdfDoc.context.obj({});
            stdCFDict.set(pdf_lib_1.PDFName.of('CFM'), pdf_lib_1.PDFName.of('AESV3'));
            stdCFDict.set(pdf_lib_1.PDFName.of('AuthEvent'), pdf_lib_1.PDFName.of(options.ownerPassword ? 'DocOpen' : 'EFOpen'));
            stdCFDict.set(pdf_lib_1.PDFName.of('Length'), pdf_lib_1.PDFNumber.of(algorithm === 'AES-256' ? 32 : 16));
            cfDict.set(pdf_lib_1.PDFName.of('StdCF'), stdCFDict);
            encryptDict.set(pdf_lib_1.PDFName.of('CF'), cfDict);
            encryptDict.set(pdf_lib_1.PDFName.of('StmF'), pdf_lib_1.PDFName.of('StdCF'));
            encryptDict.set(pdf_lib_1.PDFName.of('StrF'), pdf_lib_1.PDFName.of('StdCF'));
        }
        const userKeyHex = this.padKey(userKey, 32).toString('hex');
        const ownerKeyHex = this.padKey(ownerKey, 32).toString('hex');
        encryptDict.set(pdf_lib_1.PDFName.of('U'), pdf_lib_1.PDFHexString.of(userKeyHex));
        encryptDict.set(pdf_lib_1.PDFName.of('O'), pdf_lib_1.PDFHexString.of(ownerKeyHex));
        encryptDict.set(pdf_lib_1.PDFName.of('P'), pdf_lib_1.PDFNumber.of(permissions));
        if (algorithm !== 'RC4-128' && options.kdf) {
            encryptDict.set(pdf_lib_1.PDFName.of('Salt'), pdf_lib_1.PDFHexString.of(salt.toString('hex')));
            encryptDict.set(pdf_lib_1.PDFName.of('Iterations'), pdf_lib_1.PDFNumber.of(options.kdf.iterations || 10000));
        }
        return encryptDict;
    }
    static calculatePermissions(permissions) {
        let flags = 0xfffff0c0;
        if (permissions) {
            if (permissions.printing)
                flags |= this.PERMISSIONS_FLAGS.printing;
            if (permissions.modifying)
                flags |= this.PERMISSIONS_FLAGS.modifying;
            if (permissions.copying)
                flags |= this.PERMISSIONS_FLAGS.copying;
            if (permissions.annotating)
                flags |= this.PERMISSIONS_FLAGS.annotating;
            if (permissions.fillingForms)
                flags |= this.PERMISSIONS_FLAGS.fillingForms;
            if (permissions.contentAccessibility)
                flags |= this.PERMISSIONS_FLAGS.contentAccessibility;
            if (permissions.documentAssembly)
                flags |= this.PERMISSIONS_FLAGS.documentAssembly;
            if (permissions.highQualityPrinting)
                flags |= this.PERMISSIONS_FLAGS.highQualityPrinting;
        }
        return flags;
    }
    static padKey(key, length) {
        if (key.length >= length)
            return key.subarray(0, length);
        const padded = Buffer.alloc(length);
        key.copy(padded);
        return padded;
    }
    static generateOutputPath(inputPath, suffix = '_encrypted') {
        const dir = (0, path_1.dirname)(inputPath);
        const base = (0, path_1.basename)(inputPath, '.pdf');
        return (0, path_1.join)(dir, `${base}${suffix}.pdf`);
    }
}
exports.PDFEncryptor = PDFEncryptor;
//# sourceMappingURL=encryptor.js.map