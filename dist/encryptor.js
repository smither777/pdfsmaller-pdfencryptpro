"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PDFEncryptor = void 0;
const pdf_lib_1 = require("pdf-lib");
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
    static async encryptPDF(pdfBytes, options) {
        const pdfDoc = await pdf_lib_1.PDFDocument.load(pdfBytes);
        const algorithm = options.algorithm || 'AES-256';
        const userPassword = options.userPassword;
        const ownerPassword = options.ownerPassword || userPassword;
        const salt = crypto_1.CryptoEngine.generateSalt();
        const userKey = await crypto_1.CryptoEngine.deriveKey(userPassword, salt, algorithm, options.kdf);
        const ownerKey = await crypto_1.CryptoEngine.deriveKey(ownerPassword, salt, algorithm, options.kdf);
        const permissions = this.calculatePermissions(options.permissions);
        const encryptDict = await this.createEncryptionDictionary(pdfDoc, algorithm, userKey, ownerKey, salt, permissions, options);
        pdfDoc.context.trailerInfo.Encrypt = pdfDoc.context.register(encryptDict);
        if (options.enableHMAC) {
            const documentId = pdfDoc.context.trailerInfo.ID;
            if (documentId && Array.isArray(documentId)) {
                const hmacKey = await crypto_1.CryptoEngine.deriveKey(userPassword + ownerPassword, salt, algorithm, options.kdf);
                const documentBytes = await pdfDoc.save();
                const hmac = await crypto_1.CryptoEngine.generateHMAC(new Uint8Array(documentBytes), hmacKey);
                encryptDict.set(pdf_lib_1.PDFName.of('HMAC'), pdf_lib_1.PDFHexString.of(this.uint8ArrayToHex(hmac)));
            }
        }
        const encryptedBytes = await pdfDoc.save({
            useObjectStreams: false,
        });
        return new Uint8Array(encryptedBytes);
    }
    static async encryptPDFWithMetadata(pdfBytes, options) {
        const startTime = Date.now();
        try {
            const encryptedBytes = await this.encryptPDF(pdfBytes, options);
            const metadata = {
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
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
            };
        }
    }
    static async createEncryptionDictionary(pdfDoc, algorithm, userKey, ownerKey, salt, permissions, options) {
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
        const userKeyHex = this.uint8ArrayToHex(this.padKey(userKey, 32));
        const ownerKeyHex = this.uint8ArrayToHex(this.padKey(ownerKey, 32));
        encryptDict.set(pdf_lib_1.PDFName.of('U'), pdf_lib_1.PDFHexString.of(userKeyHex));
        encryptDict.set(pdf_lib_1.PDFName.of('O'), pdf_lib_1.PDFHexString.of(ownerKeyHex));
        encryptDict.set(pdf_lib_1.PDFName.of('P'), pdf_lib_1.PDFNumber.of(permissions));
        if (algorithm !== 'RC4-128' && options.kdf) {
            encryptDict.set(pdf_lib_1.PDFName.of('Salt'), pdf_lib_1.PDFHexString.of(this.uint8ArrayToHex(salt)));
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
            return key.slice(0, length);
        const padded = new Uint8Array(length);
        padded.set(key);
        return padded;
    }
    static uint8ArrayToHex(array) {
        return Array.from(array)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }
}
exports.PDFEncryptor = PDFEncryptor;
//# sourceMappingURL=encryptor.js.map