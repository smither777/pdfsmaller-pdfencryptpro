#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const fs_1 = require("fs");
const path_1 = require("path");
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const encryptor_1 = require("./encryptor");
const program = new commander_1.Command();
program
    .name('pdf-encrypt-pro')
    .description('Professional PDF encryption by PDFSmaller.com with AES-256, PBKDF2, and HMAC')
    .version('1.0.0')
    .argument('<input>', 'Input PDF file path')
    .option('-o, --output <path>', 'Output PDF file path')
    .option('-p, --password <password>', 'User password (required)')
    .option('-op, --owner-password <password>', 'Owner password (defaults to user password)')
    .option('-a, --algorithm <algorithm>', 'Encryption algorithm (AES-256, AES-128, RC4-128)', 'AES-256')
    .option('-i, --iterations <number>', 'PBKDF2 iterations', '10000')
    .option('--hmac', 'Enable HMAC for document integrity')
    .option('--no-printing', 'Disable printing')
    .option('--no-copying', 'Disable copying')
    .option('--no-modifying', 'Disable modifying')
    .option('--no-annotating', 'Disable annotating')
    .option('--no-forms', 'Disable form filling')
    .option('--verbose', 'Verbose output')
    .action(async (input, options) => {
    console.log(chalk_1.default.cyan('\n╔════════════════════════════════════════╗'));
    console.log(chalk_1.default.cyan('║     PDFSmaller.com Encrypt Pro v1.0    ║'));
    console.log(chalk_1.default.cyan('║   Enterprise-Grade PDF Encryption      ║'));
    console.log(chalk_1.default.cyan('╚════════════════════════════════════════╝\n'));
    const spinner = (0, ora_1.default)();
    try {
        if (!options.password) {
            console.error(chalk_1.default.red('Error: Password is required'));
            process.exit(1);
        }
        const inputPath = (0, path_1.resolve)(input);
        if (!(0, fs_1.existsSync)(inputPath)) {
            console.error(chalk_1.default.red(`Error: Input file not found: ${inputPath}`));
            process.exit(1);
        }
        const stats = (0, fs_1.statSync)(inputPath);
        if (!stats.isFile() || !inputPath.toLowerCase().endsWith('.pdf')) {
            console.error(chalk_1.default.red('Error: Input must be a PDF file'));
            process.exit(1);
        }
        const outputPath = options.output
            ? (0, path_1.resolve)(options.output)
            : generateOutputPath(inputPath, '_encrypted');
        const algorithm = options.algorithm.toUpperCase();
        if (!['AES-256', 'AES-128', 'RC4-128'].includes(algorithm)) {
            console.error(chalk_1.default.red('Error: Invalid algorithm. Use AES-256, AES-128, or RC4-128'));
            process.exit(1);
        }
        const encryptionOptions = {
            userPassword: options.password,
            ownerPassword: options.ownerPassword,
            algorithm,
            kdf: {
                iterations: parseInt(options.iterations, 10),
            },
            enableHMAC: options.hmac,
            permissions: {
                printing: options.printing !== false,
                copying: options.copying !== false,
                modifying: options.modifying !== false,
                annotating: options.annotating !== false,
                fillingForms: options.forms !== false,
                contentAccessibility: true,
                documentAssembly: true,
                highQualityPrinting: options.printing !== false,
            },
        };
        if (options.verbose) {
            console.log(chalk_1.default.cyan('Encryption Settings:'));
            console.log(`  Algorithm: ${algorithm}`);
            console.log(`  PBKDF2 Iterations: ${encryptionOptions.kdf?.iterations}`);
            console.log(`  HMAC: ${encryptionOptions.enableHMAC ? 'Enabled' : 'Disabled'}`);
            console.log(`  Input: ${inputPath}`);
            console.log(`  Output: ${outputPath}`);
        }
        spinner.start(chalk_1.default.yellow('Encrypting PDF...'));
        const pdfBytes = new Uint8Array((0, fs_1.readFileSync)(inputPath));
        const result = await encryptor_1.PDFEncryptor.encryptPDFWithMetadata(pdfBytes, encryptionOptions);
        if (result.success && result.encryptedBytes) {
            (0, fs_1.writeFileSync)(outputPath, result.encryptedBytes);
            spinner.succeed(chalk_1.default.green('PDF encrypted successfully!'));
            if (options.verbose && result.metadata) {
                console.log(chalk_1.default.cyan('\\nEncryption Details:'));
                console.log(`  Algorithm: ${result.metadata.algorithm}`);
                console.log(`  KDF Iterations: ${result.metadata.kdfIterations}`);
                console.log(`  HMAC: ${result.metadata.hmacEnabled ? 'Enabled' : 'Disabled'}`);
                console.log(`  Output Size: ${(result.metadata.fileSize / 1024).toFixed(2)} KB`);
                console.log(`  Time: ${result.metadata.encryptionTime} ms`);
            }
            console.log(chalk_1.default.blue(`\\nOutput: ${outputPath}`));
        }
        else {
            spinner.fail(chalk_1.default.red('Encryption failed'));
            console.error(chalk_1.default.red(`Error: ${result.error}`));
            process.exit(1);
        }
    }
    catch (error) {
        spinner.fail(chalk_1.default.red('Unexpected error'));
        console.error(chalk_1.default.red(`Error: ${error instanceof Error ? error.message : error}`));
        process.exit(1);
    }
});
function generateOutputPath(inputPath, suffix = '_encrypted') {
    const dir = (0, path_1.dirname)(inputPath);
    const base = (0, path_1.basename)(inputPath, '.pdf');
    return (0, path_1.join)(dir, `${base}${suffix}.pdf`);
}
program.parse();
//# sourceMappingURL=cli-node.js.map