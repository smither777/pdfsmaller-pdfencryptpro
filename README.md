# pdf-encrypt-pro 🔐

**Enterprise-grade PDF encryption with AES-256, PBKDF2, and HMAC - Works everywhere: Edge, Browser, Node.js!**

Built by [PDFSmaller.com](https://pdfsmaller.com) - The ONLY AES-256 PDF encryption library that works in Cloudflare Workers!

[![NPM Version](https://img.shields.io/npm/v/@pdfsmaller/pdf-encrypt-pro.svg)](https://www.npmjs.com/package/@pdfsmaller/pdf-encrypt-pro)
[![Edge Compatible](https://img.shields.io/badge/Edge-Compatible-green)](https://developers.cloudflare.com/workers/)
[![License](https://img.shields.io/npm/l/@pdfsmaller/pdf-encrypt-pro.svg)](https://github.com/smither777/pdfsmaller-pdfencryptpro/blob/main/LICENSE)
[![Powered by PDFSmaller](https://img.shields.io/badge/Powered%20by-PDFSmaller.com-blue)](https://pdfsmaller.com)

## 🚀 Why pdf-encrypt-pro?

**The ONLY professional PDF encryption library that works in edge environments!**

When [PDFSmaller.com](https://pdfsmaller.com) users needed bank-level PDF security that works everywhere - from Cloudflare Workers to browsers to Node.js - we built this. While other "enterprise" libraries are stuck in Node.js, we deliver:

- **AES-256 encryption** using Web Crypto API (works in edge!)
- **PBKDF2 key derivation** to prevent brute-force attacks  
- **HMAC integrity verification** to detect tampering
- **Runs EVERYWHERE** - Cloudflare Workers, Vercel Edge, browsers, Node.js

**This is enterprise PDF security that actually works in modern environments.**

### The Security Stack We Built:
- ✅ **AES-256**: NSA-approved encryption standard
- ✅ **PBKDF2**: 10,000+ iterations for key strengthening
- ✅ **HMAC-SHA256**: Cryptographic integrity verification
- ✅ **Full permission control**: 8 granular permission flags
- ✅ **TypeScript**: Type-safe implementation

## ✨ Features

- 🌐 **Edge Compatible** - Works in Cloudflare Workers, Vercel Edge, Deno Deploy
- 🔐 **AES-256 Encryption** - Using Web Crypto API for universal compatibility
- 🔑 **PBKDF2 Key Derivation** - Configurable iterations (default: 10,000)
- 🛡️ **HMAC Integrity** - Detect document tampering
- 📋 **Multiple Algorithms** - AES-256, AES-128, RC4-128
- 🎛️ **Granular Permissions** - Control printing, copying, editing, etc.
- 💼 **Enterprise Ready** - FIPS & ISO compliance compatible
- ⚡ **Zero Node.js Dependencies** - Pure Web Crypto API
- 🖥️ **CLI Tool** - Command-line automation for Node.js
- 📘 **Full TypeScript** - Complete type definitions

## 📥 Installation

```bash
npm install @pdfsmaller/pdf-encrypt-pro
```

Or install globally for CLI usage:

```bash
npm install -g @pdfsmaller/pdf-encrypt-pro
```

## 💻 Usage

### Command Line

```bash
# Basic AES-256 encryption
pdf-encrypt-pro document.pdf -p "strongPassword123"

# Advanced security with HMAC
pdf-encrypt-pro document.pdf \
  -o secured.pdf \
  -p "userPass" \
  -op "ownerPass" \
  -a AES-256 \
  -i 10000 \
  --hmac \
  --no-printing \
  --no-copying
```

### Edge/Browser Usage (Cloudflare Workers, Vercel Edge, Browser)

```javascript
import { encryptPDF } from '@pdfsmaller/pdf-encrypt-pro';

// Simple API for edge environments
const encryptedBytes = await encryptPDF(
  pdfBytes,
  'userPassword',
  'ownerPassword',
  {
    algorithm: 'AES-256',
    enableHMAC: true,
    iterations: 10000
  }
);
```

### Node.js Usage

```javascript
import { PDFEncryptor } from '@pdfsmaller/pdf-encrypt-pro';

// Basic AES-256 encryption
const result = await PDFEncryptor.encryptPDF(
  'document.pdf',
  'encrypted.pdf',
  {
    userPassword: 'secretPassword123',
    algorithm: 'AES-256'
  }
);

// Enterprise security with HMAC
const result = await PDFEncryptor.encryptPDF(
  'sensitive.pdf',
  'secured.pdf',
  {
    userPassword: 'userPass123',
    ownerPassword: 'ownerPass456',
    algorithm: 'AES-256',
    kdf: {
      iterations: 10000,
      saltLength: 16
    },
    enableHMAC: true,
    permissions: {
      printing: false,
      copying: false,
      modifying: false
    }
  }
);

if (result.success) {
  console.log(`✅ Encrypted: ${result.outputPath}`);
  console.log(`⏱️ Time: ${result.metadata.encryptionTime}ms`);
}
```

## 🔥 Use Cases

Perfect for:
- **Edge Functions** - Cloudflare Workers, Vercel Edge, Netlify Functions
- **Browser Applications** - Client-side encryption without server uploads
- **Banking & Finance** - Regulatory compliance (SOX, PCI-DSS)
- **Healthcare** - HIPAA-compliant document protection
- **Legal** - Confidential document security
- **Enterprise** - Internal document control
- **Serverless** - AWS Lambda, Google Cloud Functions

## 🎯 Real-World Example

This library powers enterprise features at [PDFSmaller.com](https://pdfsmaller.com/protect-pdf) - handling thousands of sensitive documents daily with bank-level security.

## 🏗️ How It Works

1. **Password Processing**: PBKDF2 derives cryptographic keys from passwords
2. **Content Encryption**: AES-256-CBC encrypts all PDF streams
3. **Integrity Protection**: HMAC-SHA256 signs the encrypted document
4. **Permission Enforcement**: Granular flags control document usage
5. **Standard Compliance**: Implements PDF 2.0 encryption specifications

## 📊 Comparison

### The Edge Advantage

| Feature | pdf-encrypt-pro | Other Libraries |
|---------|-----------------|------------------|
| **Works in Cloudflare Workers** | ✅ | ❌ |
| **Works in Vercel Edge** | ✅ | ❌ |
| **Works in Browser** | ✅ | ❌ |
| **AES-256 Encryption** | ✅ | ✅ |
| **PBKDF2** | ✅ | ✅ |
| **HMAC** | ✅ | ⚠️ |
| **No Node.js Required** | ✅ | ❌ |

### vs. pdf-encrypt-lite

| Feature | pdf-encrypt-lite | pdf-encrypt-pro |
|---------|-----------------|-----------------|
| **Encryption** | RC4-128 | AES-256, AES-128, RC4-128 |
| **Key Derivation** | MD5 | PBKDF2 (10,000+ iterations) |
| **Integrity Check** | ❌ | HMAC-SHA256 |
| **Permissions** | Basic | 8 Granular Controls |
| **Package Size** | ~7KB | ~45KB |
| **Use Case** | Basic Protection | Enterprise Security |
| **Compliance** | Basic | FIPS, ISO, HIPAA Ready |

### vs. Other Libraries

| Library | AES-256 | PBKDF2 | HMAC | TypeScript | CLI |
|---------|---------|--------|------|------------|-----|
| **pdf-encrypt-pro** | ✅ | ✅ | ✅ | ✅ | ✅ |
| node-forge | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| pdf-lib alone | ❌ | ❌ | ❌ | ✅ | ❌ |
| qpdf | ✅ | ⚠️ | ❌ | ❌ | ✅ |

## 🔒 Security Features

### AES-256 Encryption
- **Standard**: FIPS 197, ISO/IEC 18033-3
- **Key Size**: 256 bits
- **Mode**: CBC with random IV
- **Padding**: PKCS#7

### PBKDF2 Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: Configurable (default: 10,000)
- **Salt**: Cryptographically random 16 bytes
- **Output**: Encryption & authentication keys

### HMAC Integrity
- **Algorithm**: HMAC-SHA256
- **Coverage**: Full document post-encryption
- **Verification**: Automatic on PDF open
- **Protection**: Detects any tampering

## 🎛️ CLI Options

```
Options:
  -o, --output <path>              Output file path
  -p, --password <password>        User password (required)
  -op, --owner-password <password> Owner password
  -a, --algorithm <type>           AES-256|AES-128|RC4-128 (default: AES-256)
  -i, --iterations <number>        PBKDF2 iterations (default: 10000)
  --hmac                           Enable HMAC integrity
  --no-printing                    Disable printing
  --no-copying                     Disable copying
  --no-modifying                   Disable modifying
  --no-annotating                  Disable annotations
  --no-forms                       Disable form filling
  --verbose                        Show detailed output
```

## 📚 API Reference

### `PDFEncryptor.encryptPDF(input, output, options)`

```typescript
interface EncryptionOptions {
  userPassword: string;
  ownerPassword?: string;
  algorithm?: 'AES-256' | 'AES-128' | 'RC4-128';
  kdf?: {
    iterations?: number;  // Default: 10000
    saltLength?: number;  // Default: 16
  };
  enableHMAC?: boolean;
  permissions?: {
    printing?: boolean;
    modifying?: boolean;
    copying?: boolean;
    annotating?: boolean;
    fillingForms?: boolean;
    contentAccessibility?: boolean;
    documentAssembly?: boolean;
    highQualityPrinting?: boolean;
  };
}
```

## 🤝 Contributing

We welcome contributions! This library powers [PDFSmaller.com](https://pdfsmaller.com)'s enterprise features, so we maintain strict security and quality standards.

## 📜 License

MIT License - Use it freely in your projects!

## 🙏 Credits

Built with 🔒 by [PDFSmaller.com](https://pdfsmaller.com) - Your trusted PDF security partner

Check out our complete PDF toolkit:
- [Protect PDF](https://pdfsmaller.com/protect-pdf) - Uses this library!
- [Compress PDF](https://pdfsmaller.com/compress-pdf) - Reduce size by 90%
- [Merge PDF](https://pdfsmaller.com/merge-pdf) - Combine documents
- [Split PDF](https://pdfsmaller.com/split-pdf) - Extract pages
- [20+ more tools](https://pdfsmaller.com) - All secure, all private

## 🚀 Quick Start Examples

### Cloudflare Workers (Edge)
```javascript
export default {
  async fetch(request, env) {
    const formData = await request.formData();
    const file = formData.get('pdf');
    const password = formData.get('password');
    
    const pdfBytes = new Uint8Array(await file.arrayBuffer());
    
    // Works perfectly in edge environment!
    const encrypted = await encryptPDF(pdfBytes, password, password, {
      algorithm: 'AES-256',
      enableHMAC: true
    });
    
    return new Response(encrypted, {
      headers: { 'Content-Type': 'application/pdf' }
    });
  }
}
```

### Vercel Edge Functions
```javascript
import { encryptPDF } from '@pdfsmaller/pdf-encrypt-pro';

export const config = { runtime: 'edge' };

export default async function handler(request) {
  const { pdf, password } = await request.json();
  const pdfBytes = new Uint8Array(Buffer.from(pdf, 'base64'));
  
  const encrypted = await encryptPDF(pdfBytes, password, password, {
    algorithm: 'AES-256',
    enableHMAC: true,
    iterations: 10000
  });
  
  return new Response(encrypted, {
    headers: { 'Content-Type': 'application/pdf' }
  });
}
```

### Browser (Client-side)
```javascript
import { encryptPDF } from '@pdfsmaller/pdf-encrypt-pro';

async function protectPDF(file, password) {
  const arrayBuffer = await file.arrayBuffer();
  const pdfBytes = new Uint8Array(arrayBuffer);
  
  // Encrypt directly in the browser!
  const encrypted = await encryptPDF(pdfBytes, password, password, {
    algorithm: 'AES-256',
    enableHMAC: true
  });
  
  // Download the encrypted PDF
  const blob = new Blob([encrypted], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'encrypted.pdf';
  a.click();
}
```

### Node.js/Express
```javascript
app.post('/encrypt', upload.single('pdf'), async (req, res) => {
  const result = await PDFEncryptor.encryptPDF(
    req.file.path,
    'output.pdf',
    {
      userPassword: req.body.password,
      algorithm: 'AES-256',
      enableHMAC: true
    }
  );
  
  res.download(result.outputPath);
});
```

### AWS Lambda
```javascript
exports.handler = async (event) => {
  const pdfBuffer = Buffer.from(event.body, 'base64');
  
  const result = await PDFEncryptor.encryptPDF(
    pdfBuffer,
    '/tmp/encrypted.pdf',
    {
      userPassword: event.password,
      algorithm: 'AES-256',
      kdf: { iterations: 10000 },
      enableHMAC: true
    }
  );
  
  return {
    statusCode: 200,
    body: fs.readFileSync(result.outputPath).toString('base64')
  };
};
```

## 📧 Support

- 🐛 [Report issues](https://github.com/smither777/pdfsmaller-pdfencryptpro/issues)
- 💡 [Request features](https://github.com/smither777/pdfsmaller-pdfencryptpro/issues)
- 🌐 [Visit PDFSmaller.com](https://pdfsmaller.com)
- 📧 [Contact us](https://pdfsmaller.com/contact)

---

**⭐ Star this repo if it helps secure your PDFs!**

*Built for enterprise. Trusted by professionals.*

[PDFSmaller.com](https://pdfsmaller.com) - Enterprise PDF Security That Actually Works™