"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.publicKeyCompress = exports.OmnichainCrypto = void 0;
var elliptic = require("elliptic");
var OmnichainCrypto = /** @class */ (function () {
    function OmnichainCrypto(hashFun, curveName, keyPair) {
        var _this = this;
        this.sign2buffer = function (msg) {
            if (_this.priKey.length != 32) {
                throw ("Invalid private key to sign!");
            }
            var key = _this.ec.keyFromPrivate(_this.priKey);
            var sig = key.sign(_this.hashFun(msg));
            var n = 32;
            var r = sig.r.toArrayLike(Buffer, 'be', n);
            var s = sig.s.toArrayLike(Buffer, 'be', n);
            return Buffer.concat([r, s]);
        };
        this.sign2hexstring = function (msg) {
            return _this.sign2buffer(msg).toString('hex');
        };
        this.sign2bufferrecovery = function (msg) {
            if (_this.priKey.length != 32) {
                throw ("Invalid private key to sign!");
            }
            var key = _this.ec.keyFromPrivate(_this.priKey);
            var sig = key.sign(_this.hashFun(msg));
            var n = 32;
            var r = sig.r.toArrayLike(Buffer, 'be', n);
            var s = sig.s.toArrayLike(Buffer, 'be', n);
            return Buffer.concat([r, s, Buffer.from([sig.recoveryParam + 27])]);
        };
        this.sign2hexstringrecovery = function (msg) {
            return _this.sign2bufferrecovery(msg).toString('hex');
        };
        this.sign = function (msg) {
            if (_this.priKey.length != 32) {
                throw ("Invalid private key to sign!");
            }
            var key = _this.ec.keyFromPrivate(_this.priKey);
            var sig = key.sign(_this.hashFun(msg));
            return sig;
        };
        this.verify = function (msg, signature) {
            if ((_this.pubKey.length != 65) && (_this.pubKey.length != 33)) {
                throw ("Invalid public key to verify!");
            }
            var msgHash = _this.hashFun(msg);
            var key = _this.ec.keyFromPublic(_this.pubKey);
            return key.verify(msgHash, signature, _this.pubKey);
        };
        this.hashFun = hashFun;
        this.ec = new elliptic.ec(curveName);
        if (typeof keyPair == 'undefined') {
            var keyPair_1 = this.ec.genKeyPair();
            this.pubKey = Buffer.from(keyPair_1.getPublic('hex'), 'hex');
            this.priKey = Buffer.from(keyPair_1.getPrivate('hex'), 'hex');
        }
        else {
            this.pubKey = Buffer.from(keyPair[0], 'hex');
            this.priKey = Buffer.from(keyPair[1], 'hex');
        }
        if (this.pubKey.length === 64) {
            this.pubKey = Buffer.concat([Buffer.from([4]), this.pubKey]);
        }
        else if (this.pubKey.length === 33 || this.pubKey.length === 0) {
            // do nothing
        }
        else {
            throw ("Invalid public key!");
        }
        if ((this.priKey.length != 0) && (this.priKey.length != 32)) {
            throw ("Invalid private key!");
        }
    }
    return OmnichainCrypto;
}());
exports.OmnichainCrypto = OmnichainCrypto;
function publicKeyCompress(pubKey) {
    return __awaiter(this, void 0, void 0, function () {
        var y, _1n, flag, x, finalX, finalXArray;
        return __generator(this, function (_a) {
            if (pubKey.length == 128) {
                y = "0x" + pubKey.substring(64);
                _1n = BigInt(1);
                flag = BigInt(y) & _1n ? '03' : '02';
                x = Buffer.from(pubKey.substring(0, 64), "hex");
                finalX = Buffer.concat([Buffer.from(flag, 'hex'), x]);
                finalXArray = new Uint8Array(finalX);
                // console.log("Public Key: \n"+ finalXArray);
                return [2 /*return*/, finalXArray];
            }
            else {
                throw ("Invalid public key length!" + pubKey.length);
            }
            return [2 /*return*/];
        });
    });
}
exports.publicKeyCompress = publicKeyCompress;
