#!/usr/bin/env node

import { Command } from 'commander';
import { existsSync, statSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { PDFEncryptor } from './encryptor';
import { EncryptionOptions, EncryptionAlgorithm } from './types';

const program = new Command();

program
  .name('pdf-encrypt-pro')
  .description('Professional PDF encryption by PDFSmaller.com with AES-256, PBKDF2, and HMAC')
  .version('1.0.0')
  .argument('<input>', 'Input PDF file path')
  .option('-o, --output <path>', 'Output PDF file path')
  .option('-p, --password <password>', 'User password (required)')
  .option('-op, --owner-password <password>', 'Owner password (defaults to user password)')
  .option(
    '-a, --algorithm <algorithm>',
    'Encryption algorithm (AES-256, AES-128, RC4-128)',
    'AES-256',
  )
  .option('-i, --iterations <number>', 'PBKDF2 iterations', '10000')
  .option('--hmac', 'Enable HMAC for document integrity')
  .option('--no-printing', 'Disable printing')
  .option('--no-copying', 'Disable copying')
  .option('--no-modifying', 'Disable modifying')
  .option('--no-annotating', 'Disable annotating')
  .option('--no-forms', 'Disable form filling')
  .option('--verbose', 'Verbose output')
  .action(async (input, options) => {
    console.log(chalk.cyan('\n╔════════════════════════════════════════╗'));
    console.log(chalk.cyan('║     PDFSmaller.com Encrypt Pro v1.0    ║'));
    console.log(chalk.cyan('║   Enterprise-Grade PDF Encryption      ║'));
    console.log(chalk.cyan('╚════════════════════════════════════════╝\n'));

    const spinner = ora();

    try {
      if (!options.password) {
        console.error(chalk.red('Error: Password is required'));
        process.exit(1);
      }

      const inputPath = resolve(input);
      if (!existsSync(inputPath)) {
        console.error(chalk.red(`Error: Input file not found: ${inputPath}`));
        process.exit(1);
      }

      const stats = statSync(inputPath);
      if (!stats.isFile() || !inputPath.toLowerCase().endsWith('.pdf')) {
        console.error(chalk.red('Error: Input must be a PDF file'));
        process.exit(1);
      }

      const outputPath = options.output
        ? resolve(options.output)
        : PDFEncryptor.generateOutputPath(inputPath, '_encrypted');

      const algorithm = options.algorithm.toUpperCase() as EncryptionAlgorithm;
      if (!['AES-256', 'AES-128', 'RC4-128'].includes(algorithm)) {
        console.error(chalk.red('Error: Invalid algorithm. Use AES-256, AES-128, or RC4-128'));
        process.exit(1);
      }

      const encryptionOptions: EncryptionOptions = {
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
        console.log(chalk.cyan('Encryption Settings:'));
        console.log(`  Algorithm: ${algorithm}`);
        console.log(`  PBKDF2 Iterations: ${encryptionOptions.kdf?.iterations}`);
        console.log(`  HMAC: ${encryptionOptions.enableHMAC ? 'Enabled' : 'Disabled'}`);
        console.log(`  Input: ${inputPath}`);
        console.log(`  Output: ${outputPath}`);
      }

      spinner.start(chalk.yellow('Encrypting PDF...'));

      const result = await PDFEncryptor.encryptPDF(inputPath, outputPath, encryptionOptions);

      if (result.success) {
        spinner.succeed(chalk.green('PDF encrypted successfully!'));

        if (options.verbose && result.metadata) {
          console.log(chalk.cyan('\\nEncryption Details:'));
          console.log(`  Algorithm: ${result.metadata.algorithm}`);
          console.log(`  KDF Iterations: ${result.metadata.kdfIterations}`);
          console.log(`  HMAC: ${result.metadata.hmacEnabled ? 'Enabled' : 'Disabled'}`);
          console.log(`  Output Size: ${(result.metadata.fileSize! / 1024).toFixed(2)} KB`);
          console.log(`  Time: ${result.metadata.encryptionTime} ms`);
        }

        console.log(chalk.blue(`\\nOutput: ${result.outputPath}`));
      } else {
        spinner.fail(chalk.red('Encryption failed'));
        console.error(chalk.red(`Error: ${result.error}`));
        process.exit(1);
      }
    } catch (error) {
      spinner.fail(chalk.red('Unexpected error'));
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : error}`));
      process.exit(1);
    }
  });

program.parse();