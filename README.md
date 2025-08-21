# @pdfsmaller/pdf-encrypt-pro

Professional PDF encryption library by [PDFSmaller.com](https://pdfsmaller.com) with enterprise-grade security features including AES-256 encryption, PBKDF2 key derivation, and HMAC integrity verification.

A product of PDFSmaller.com - Your trusted PDF processing solution.

## Features

- **AES-256 Encryption**: Industry-standard strong encryption
- **AES-128 Encryption**: Balanced security and performance
- **RC4-128 Encryption**: Legacy support for compatibility
- **PBKDF2 Key Derivation**: Protection against brute-force attacks
- **HMAC Integrity**: Document tampering detection
- **Granular Permissions**: Control printing, copying, modifying, and more
- **TypeScript Support**: Full type definitions included
- **CLI Tool**: Command-line interface for easy automation

## Installation

```bash
npm install @pdfsmaller/pdf-encrypt-pro
```

Or install globally for CLI usage:

```bash
npm install -g @pdfsmaller/pdf-encrypt-pro
```

## Usage

### Command Line Interface

Basic encryption with AES-256:
```bash
pdf-encrypt-pro input.pdf -p "strongPassword123"
```

Advanced options:
```bash
pdf-encrypt-pro input.pdf \
  -o output.pdf \
  -p "userPassword" \
  -op "ownerPassword" \
  -a AES-256 \
  -i 10000 \
  --hmac \
  --no-printing \
  --no-copying \
  --verbose
```

#### CLI Options

- `-o, --output <path>`: Output PDF file path
- `-p, --password <password>`: User password (required)
- `-op, --owner-password <password>`: Owner password (defaults to user password)
- `-a, --algorithm <algorithm>`: Encryption algorithm (AES-256, AES-128, RC4-128)
- `-i, --iterations <number>`: PBKDF2 iterations (default: 10000)
- `--hmac`: Enable HMAC for document integrity
- `--no-printing`: Disable printing
- `--no-copying`: Disable copying
- `--no-modifying`: Disable modifying
- `--no-annotating`: Disable annotating
- `--no-forms`: Disable form filling
- `--verbose`: Verbose output

### Programmatic API

```javascript
import { PDFEncryptor } from '@pdfsmaller/pdf-encrypt-pro';

// Basic encryption
const result = await PDFEncryptor.encryptPDF(
  'input.pdf',
  'output.pdf',
  {
    userPassword: 'secretPassword123',
    algorithm: 'AES-256'
  }
);

if (result.success) {
  console.log('PDF encrypted successfully!');
  console.log('Output:', result.outputPath);
  console.log('Encryption time:', result.metadata.encryptionTime, 'ms');
}
```

#### Advanced Example

```javascript
import { PDFEncryptor } from '@pdfsmaller/pdf-encrypt-pro';

const result = await PDFEncryptor.encryptPDF(
  'sensitive-document.pdf',
  'secured-document.pdf',
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
      modifying: false,
      copying: false,
      annotating: true,
      fillingForms: true,
      contentAccessibility: true,
      documentAssembly: false,
      highQualityPrinting: false
    }
  }
);

if (result.success) {
  console.log('Encryption metadata:', result.metadata);
} else {
  console.error('Encryption failed:', result.error);
}
```

## API Reference

### `PDFEncryptor.encryptPDF(inputPath, outputPath, options)`

Encrypts a PDF file with the specified options.

#### Parameters

- `inputPath` (string): Path to the input PDF file
- `outputPath` (string): Path for the encrypted output PDF
- `options` (EncryptionOptions): Encryption configuration

#### EncryptionOptions

```typescript
interface EncryptionOptions {
  userPassword: string;
  ownerPassword?: string;
  algorithm?: 'AES-256' | 'AES-128' | 'RC4-128';
  permissions?: Permissions;
  kdf?: {
    iterations?: number;
    saltLength?: number;
  };
  enableHMAC?: boolean;
}
```

#### Permissions

```typescript
interface Permissions {
  printing?: boolean;
  modifying?: boolean;
  copying?: boolean;
  annotating?: boolean;
  fillingForms?: boolean;
  contentAccessibility?: boolean;
  documentAssembly?: boolean;
  highQualityPrinting?: boolean;
}
```

#### Returns

```typescript
interface EncryptionResult {
  success: boolean;
  outputPath?: string;
  error?: string;
  metadata?: {
    algorithm: string;
    kdfIterations?: number;
    hmacEnabled?: boolean;
    fileSize?: number;
    encryptionTime?: number;
  };
}
```

## Security Features

### AES-256 Encryption
The Advanced Encryption Standard with 256-bit keys provides the highest level of security, suitable for sensitive documents and regulatory compliance.

### PBKDF2 Key Derivation
Password-Based Key Derivation Function 2 with configurable iterations makes brute-force attacks computationally expensive.

### HMAC Integrity
Hash-based Message Authentication Code ensures document integrity and detects any unauthorized modifications.

## Comparison with pdf-encrypt-lite

| Feature | pdf-encrypt-lite | pdf-encrypt-pro |
|---------|-----------------|-----------------|
| RC4-128 | ✓ | ✓ |
| AES-128 | ✗ | ✓ |
| AES-256 | ✗ | ✓ |
| PBKDF2 | ✗ | ✓ |
| HMAC | ✗ | ✓ |
| Advanced Permissions | Basic | Full |
| File Size | Smaller | Larger |
| Use Case | Basic protection | Enterprise security |

## Requirements

- Node.js >= 18.0.0
- TypeScript >= 5.0.0 (for development)

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Format code
npm run format
```

## License

MIT

## About PDFSmaller.com

[PDFSmaller.com](https://pdfsmaller.com) provides a comprehensive suite of PDF processing tools designed for both individual and enterprise use. Our tools prioritize security, performance, and ease of use.

## Author

Eric Smith - PDFSmaller.com

## Repository

[https://github.com/smither777/pdfsmaller-pdfencryptpro](https://github.com/smither777/pdfsmaller-pdfencryptpro)

## Support

For issues and feature requests, please visit the [GitHub issues page](https://github.com/smither777/pdfsmaller-pdfencryptpro/issues).