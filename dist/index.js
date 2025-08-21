"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoEngine = exports.PDFEncryptor = void 0;
var encryptor_1 = require("./encryptor");
Object.defineProperty(exports, "PDFEncryptor", { enumerable: true, get: function () { return encryptor_1.PDFEncryptor; } });
var crypto_1 = require("./crypto");
Object.defineProperty(exports, "CryptoEngine", { enumerable: true, get: function () { return crypto_1.CryptoEngine; } });
__exportStar(require("./types"), exports);
//# sourceMappingURL=index.js.map