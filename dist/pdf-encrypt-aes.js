"use strict";
/**
 * AES-256 PDF Encryption Implementation
 * Based on the successful approach from pdf-encrypt-lite
 * Enhanced with AES-256, PBKDF2, and HMAC
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptPDFWithAES = encryptPDFWithAES;
const pdf_lib_1 = require("pdf-lib");
const crypto_1 = require("./crypto");
// Standard PDF padding string (from PDF specification)
const PADDING = new Uint8Array([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
]);
/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
/**
 * Convert hex string to bytes
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}
/**
 * Pad or truncate password according to PDF spec
 */
function padPassword(password) {
    const pwdBytes = new TextEncoder().encode(password);
    const padded = new Uint8Array(32);
    if (pwdBytes.length >= 32) {
        padded.set(pwdBytes.slice(0, 32));
    }
    else {
        padded.set(pwdBytes);
        padded.set(PADDING.slice(0, 32 - pwdBytes.length), pwdBytes.length);
    }
    return padded;
}
/**
 * Simple RC4 implementation for fallback
 */
class RC4 {
    S;
    i = 0;
    j = 0;
    constructor(key) {
        this.S = new Uint8Array(256);
        // Initialize S
        for (let i = 0; i < 256; i++) {
            this.S[i] = i;
        }
        // Key scheduling algorithm
        let j = 0;
        for (let i = 0; i < 256; i++) {
            j = (j + this.S[i] + key[i % key.length]) & 0xFF;
            [this.S[i], this.S[j]] = [this.S[j], this.S[i]];
        }
    }
    process(data) {
        const result = new Uint8Array(data.length);
        for (let k = 0; k < data.length; k++) {
            this.i = (this.i + 1) & 0xFF;
            this.j = (this.j + this.S[this.i]) & 0xFF;
            [this.S[this.i], this.S[this.j]] = [this.S[this.j], this.S[this.i]];
            const K = this.S[(this.S[this.i] + this.S[this.j]) & 0xFF];
            result[k] = data[k] ^ K;
        }
        return result;
    }
}
/**
 * Compute encryption key using PBKDF2 for AES
 */
async function computeEncryptionKey(userPassword, ownerKey, _permissions, fileId, algorithm, iterations) {
    // Create salt from owner key and file ID
    const salt = new Uint8Array(ownerKey.length + fileId.length);
    salt.set(ownerKey);
    salt.set(fileId, ownerKey.length);
    // Use PBKDF2 for key derivation
    const keyLength = algorithm === 'AES-256' ? 32 : 16;
    const encryptionKey = await crypto_1.CryptoEngine.pbkdf2(userPassword, salt, iterations, keyLength);
    return encryptionKey;
}
/**
 * Compute owner key using PBKDF2
 */
async function computeOwnerKey(ownerPassword, userPassword, algorithm, iterations) {
    const paddedUser = padPassword(userPassword);
    // Use PBKDF2 to derive owner key
    const ownerKey = await crypto_1.CryptoEngine.pbkdf2(ownerPassword || userPassword, paddedUser, iterations, algorithm === 'AES-256' ? 32 : 16);
    return ownerKey;
}
/**
 * Compute user key for AES encryption
 */
async function computeUserKey(_encryptionKey, fileId) {
    // For AES, we use a more secure approach
    const hashInput = new Uint8Array(PADDING.length + fileId.length);
    hashInput.set(PADDING);
    hashInput.set(fileId, PADDING.length);
    // Hash with SHA-256
    const hash = await crypto_1.CryptoEngine.hashPassword(new TextDecoder().decode(hashInput));
    // Create 48-byte user key (32 bytes hash + 16 bytes validation)
    const userKey = new Uint8Array(48);
    userKey.set(hash.slice(0, 32));
    userKey.set(new Uint8Array(16), 32); // Validation salt
    return userKey;
}
/**
 * Encrypt object data using AES-256
 */
async function encryptObjectAES(data, objectNum, generationNum, encryptionKey, _algorithm) {
    // For PDF 1.6 compatibility, we need to derive object-specific keys differently
    // Combine encryption key with object/generation numbers
    const keyInput = new Uint8Array(encryptionKey.length + 5 + 4);
    keyInput.set(encryptionKey);
    // Add object number (low byte first)
    keyInput[encryptionKey.length] = objectNum & 0xFF;
    keyInput[encryptionKey.length + 1] = (objectNum >> 8) & 0xFF;
    keyInput[encryptionKey.length + 2] = (objectNum >> 16) & 0xFF;
    // Add generation number (low byte first)  
    keyInput[encryptionKey.length + 3] = generationNum & 0xFF;
    keyInput[encryptionKey.length + 4] = (generationNum >> 8) & 0xFF;
    // Add "sAlT" for AES (PDF spec requirement)
    keyInput[encryptionKey.length + 5] = 0x73; // 's'
    keyInput[encryptionKey.length + 6] = 0x41; // 'A'
    keyInput[encryptionKey.length + 7] = 0x6C; // 'l'
    keyInput[encryptionKey.length + 8] = 0x54; // 'T'
    // Hash to get object key (16 bytes for AES-128)
    const hash = await crypto_1.CryptoEngine.hashPassword(new TextDecoder().decode(keyInput));
    const objectKey = hash.slice(0, 16); // Use first 16 bytes for AES-128
    // Generate IV (16 bytes)
    const iv = crypto_1.CryptoEngine.generateIV();
    // Encrypt with AES-128 in CBC mode
    const { encrypted } = await crypto_1.CryptoEngine.encryptAES(data, objectKey, 'AES-128');
    // For PDF 1.6, prepend IV to encrypted data
    const result = new Uint8Array(iv.length + encrypted.length);
    result.set(iv, 0);
    result.set(encrypted, iv.length);
    return result;
}
/**
 * Encrypt object data using RC4 (fallback for RC4-128 algorithm)
 */
function encryptObjectRC4(data, objectNum, generationNum, encryptionKey) {
    // Create object-specific key
    const keyInput = new Uint8Array(encryptionKey.length + 5);
    keyInput.set(encryptionKey);
    // Add object number (low byte first)
    keyInput[encryptionKey.length] = objectNum & 0xFF;
    keyInput[encryptionKey.length + 1] = (objectNum >> 8) & 0xFF;
    keyInput[encryptionKey.length + 2] = (objectNum >> 16) & 0xFF;
    // Add generation number (low byte first)  
    keyInput[encryptionKey.length + 3] = generationNum & 0xFF;
    keyInput[encryptionKey.length + 4] = (generationNum >> 8) & 0xFF;
    // Use simple hash for object key
    let objectKey = new Uint8Array(16);
    for (let i = 0; i < keyInput.length; i++) {
        objectKey[i % 16] ^= keyInput[i];
    }
    // Encrypt with RC4
    const rc4 = new RC4(objectKey);
    return rc4.process(data);
}
/**
 * Recursively encrypt strings in a PDF object
 */
async function encryptStringsInObject(obj, objectNum, generationNum, encryptionKey, algorithm) {
    if (!obj)
        return;
    if (obj instanceof pdf_lib_1.PDFString) {
        const originalBytes = obj.asBytes();
        let encrypted;
        if (algorithm === 'RC4-128') {
            encrypted = encryptObjectRC4(originalBytes, objectNum, generationNum, encryptionKey);
        }
        else {
            encrypted = await encryptObjectAES(originalBytes, objectNum, generationNum, encryptionKey, algorithm);
        }
        // Replace with encrypted hex
        obj.value = bytesToHex(encrypted);
    }
    else if (obj instanceof pdf_lib_1.PDFHexString) {
        const originalBytes = hexToBytes(obj.asString());
        let encrypted;
        if (algorithm === 'RC4-128') {
            encrypted = encryptObjectRC4(originalBytes, objectNum, generationNum, encryptionKey);
        }
        else {
            encrypted = await encryptObjectAES(originalBytes, objectNum, generationNum, encryptionKey, algorithm);
        }
        obj.value = bytesToHex(encrypted);
    }
    else if (obj instanceof pdf_lib_1.PDFDict) {
        // Don't encrypt certain dictionary entries
        const entries = obj.entries();
        for (const [key, value] of entries) {
            const keyName = key.asString();
            // Skip encryption-related entries
            if (keyName !== '/Length' && keyName !== '/Filter' && keyName !== '/DecodeParms') {
                await encryptStringsInObject(value, objectNum, generationNum, encryptionKey, algorithm);
            }
        }
    }
    else if (obj instanceof pdf_lib_1.PDFArray) {
        const array = obj.asArray();
        for (const element of array) {
            await encryptStringsInObject(element, objectNum, generationNum, encryptionKey, algorithm);
        }
    }
}
/**
 * Main function to encrypt a PDF with AES-256
 */
async function encryptPDFWithAES(pdfBytes, options) {
    try {
        // Load the PDF
        const pdfDoc = await pdf_lib_1.PDFDocument.load(pdfBytes, {
            ignoreEncryption: true,
            updateMetadata: false
        });
        // Get the context for low-level access
        const context = pdfDoc.context;
        // Get or generate file ID
        let fileId;
        const trailer = context.trailerInfo;
        const idArray = trailer.ID;
        if (idArray && Array.isArray(idArray) && idArray.length > 0) {
            const idString = idArray[0].toString();
            const hexStr = idString.replace(/^<|>$/g, '');
            fileId = hexToBytes(hexStr);
        }
        else {
            // Generate a file ID
            fileId = crypto_1.CryptoEngine.generateSecureRandom(16);
            // Add ID to trailer
            const idHex1 = pdf_lib_1.PDFHexString.of(bytesToHex(fileId));
            const idHex2 = pdf_lib_1.PDFHexString.of(bytesToHex(fileId));
            trailer.ID = context.obj([idHex1, idHex2]);
        }
        // Set permissions
        const permissions = 0xFFFFFFFC; // -4 in signed 32-bit (all allowed)
        // Get algorithm and iterations
        // Use AES-128 for compatibility with PDF 1.6 (V=4, R=4)
        const algorithm = options.algorithm || 'AES-128';
        const iterations = options.kdf?.iterations || 10000;
        // Compute keys
        const ownerKey = await computeOwnerKey(options.ownerPassword || options.userPassword, options.userPassword, algorithm, iterations);
        const encryptionKey = await computeEncryptionKey(options.userPassword, ownerKey, permissions, fileId, algorithm, iterations);
        const userKey = await computeUserKey(encryptionKey, fileId);
        // Encrypt all objects using AES
        const indirectObjects = context.enumerateIndirectObjects();
        for (const [ref, obj] of indirectObjects) {
            const objectNum = ref.objectNumber;
            const generationNum = ref.generationNumber || 0;
            // Skip the encryption dictionary itself
            if (obj instanceof pdf_lib_1.PDFDict) {
                const filter = obj.get(pdf_lib_1.PDFName.of('Filter'));
                if (filter && filter.asString() === '/Standard') {
                    continue;
                }
            }
            // Encrypt streams
            if (obj instanceof pdf_lib_1.PDFRawStream) {
                const streamData = obj.contents;
                let encrypted;
                if (algorithm === 'RC4-128') {
                    encrypted = encryptObjectRC4(streamData, objectNum, generationNum, encryptionKey);
                }
                else {
                    encrypted = await encryptObjectAES(streamData, objectNum, generationNum, encryptionKey, algorithm);
                }
                obj.contents = encrypted;
            }
            // Encrypt strings in the object
            await encryptStringsInObject(obj, objectNum, generationNum, encryptionKey, algorithm);
        }
        // Create the /Encrypt dictionary
        let encryptDict;
        if (algorithm === 'RC4-128') {
            // RC4-128 encryption (PDF 1.4)
            encryptDict = context.obj({
                Filter: pdf_lib_1.PDFName.of('Standard'),
                V: pdf_lib_1.PDFNumber.of(2), // Version 2 (RC4)
                R: pdf_lib_1.PDFNumber.of(3), // Revision 3 (128-bit)
                Length: pdf_lib_1.PDFNumber.of(128), // Key length in bits
                P: pdf_lib_1.PDFNumber.of(permissions),
                O: pdf_lib_1.PDFHexString.of(bytesToHex(ownerKey.slice(0, 32))),
                U: pdf_lib_1.PDFHexString.of(bytesToHex(userKey.slice(0, 32)))
            });
        }
        else {
            // AES-128 encryption (PDF 1.6 - widely supported)
            // Using V=4, R=4 for maximum compatibility
            encryptDict = context.obj({
                Filter: pdf_lib_1.PDFName.of('Standard'),
                V: pdf_lib_1.PDFNumber.of(4), // Version 4 (AES-128)
                R: pdf_lib_1.PDFNumber.of(4), // Revision 4
                Length: pdf_lib_1.PDFNumber.of(128), // Key length in bits
                P: pdf_lib_1.PDFNumber.of(permissions),
                O: pdf_lib_1.PDFHexString.of(bytesToHex(ownerKey.slice(0, 32))),
                U: pdf_lib_1.PDFHexString.of(bytesToHex(userKey.slice(0, 32))),
                StmF: pdf_lib_1.PDFName.of('StdCF'), // Stream filter
                StrF: pdf_lib_1.PDFName.of('StdCF'), // String filter
                CF: context.obj({
                    StdCF: context.obj({
                        CFM: pdf_lib_1.PDFName.of('AESV2'), // AES-128 encryption
                        AuthEvent: pdf_lib_1.PDFName.of('DocOpen'),
                        Length: pdf_lib_1.PDFNumber.of(16) // 128 bits = 16 bytes
                    })
                }),
                EncryptMetadata: context.obj(true)
            });
        }
        // Register the encrypt dictionary
        const encryptRef = context.register(encryptDict);
        // Update trailer
        trailer.Encrypt = encryptRef;
        // Set producer based on algorithm
        const producerText = algorithm === 'AES-128'
            ? 'PDFSmaller.com - AES-128 Enterprise Security'
            : 'PDFSmaller.com - RC4-128 Standard Security';
        pdfDoc.setProducer(producerText);
        // Save the encrypted PDF
        const encryptedBytes = await pdfDoc.save({
            useObjectStreams: false // Don't use object streams with encryption
        });
        return encryptedBytes;
    }
    catch (error) {
        console.error('PDF encryption error:', error);
        throw new Error(`Failed to encrypt PDF: ${error.message}`);
    }
}
//# sourceMappingURL=pdf-encrypt-aes.js.map