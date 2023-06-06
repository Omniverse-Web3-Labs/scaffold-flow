import * as elliptic from 'elliptic';

export class OmnichainCrypto {

    pubKey: Buffer;
    priKey: Buffer;
    hashFun: (msg: string| Buffer) => Buffer;
    ec: any;

    constructor(hashFun: (msg: string| Buffer) => Buffer, curveName: string, keyPair?: [string, string]) {
        this.hashFun = hashFun;
        this.ec = new elliptic.ec(curveName);

        if (typeof keyPair! == 'undefined') {
            const keyPair = this.ec.genKeyPair();
            this.pubKey = Buffer.from(keyPair.getPublic('hex'), 'hex');
            this.priKey = Buffer.from(keyPair.getPrivate('hex'), 'hex');
        } else {
            this.pubKey = Buffer.from(keyPair[0], 'hex');
            this.priKey = Buffer.from(keyPair[1], 'hex');
        }

        if (this.pubKey.length === 64) {
            this.pubKey = Buffer.concat([Buffer.from([4]), this.pubKey]);
        } else if (this.pubKey.length === 33 || this.pubKey.length === 0) {
            // do nothing
        } else {
            throw("Invalid public key!");
        }

        if ((this.priKey.length != 0) && (this.priKey.length != 32)) {
            throw("Invalid private key!");
        }
    }

    sign2buffer= (msg: string | Buffer): Buffer => {
        if (this.priKey.length != 32) {
            throw("Invalid private key to sign!");
        }
        
        const key = this.ec.keyFromPrivate(this.priKey);
        const sig = key.sign(this.hashFun(msg));
        const n = 32;
        const r = sig.r.toArrayLike(Buffer, 'be', n);
        const s = sig.s.toArrayLike(Buffer, 'be', n);
        return Buffer.concat([r, s]);
    };

    sign2hexstring = (msg: string | Buffer): string => {
        return this.sign2buffer(msg).toString('hex');
    };

    sign2bufferrecovery = (msg: string | Buffer): Buffer => {
        if (this.priKey.length != 32) {
            throw("Invalid private key to sign!");
        }
        
        const key = this.ec.keyFromPrivate(this.priKey);
        const sig = key.sign(this.hashFun(msg));
        const n = 32;
        const r = sig.r.toArrayLike(Buffer, 'be', n);
        const s = sig.s.toArrayLike(Buffer, 'be', n);
        return Buffer.concat([r, s, Buffer.from([sig.recoveryParam + 27])]);
    };

    sign2hexstringrecovery = (msg: string | Buffer): string => {
        return this.sign2bufferrecovery(msg).toString('hex');
    }
 
    sign = (msg: string | Buffer): elliptic.ec.Signature => {
        if (this.priKey.length != 32) {
            throw("Invalid private key to sign!");
        }
        
        const key = this.ec.keyFromPrivate(this.priKey);
        const sig = key.sign(this.hashFun(msg));
        return sig;
    }

    verify = (msg: string | Buffer,
            signature: string | elliptic.ec.Signature) => {
        
        if ((this.pubKey.length != 65) && (this.pubKey.length != 33)) {
            throw("Invalid public key to verify!");
        }

        const msgHash = this.hashFun(msg);
        const key = this.ec.keyFromPublic(this.pubKey);
        return key.verify(msgHash, signature, this.pubKey);
    }
}

export async function publicKeyCompress(pubKey: string) {
    if (pubKey.length == 128) {
        const y = "0x" + pubKey.substring(64);
        // console.log(y);

        const _1n = BigInt(1);
        let flag = BigInt(y) & _1n ? '03' : '02';
        // console.log(flag);

        const x = Buffer.from(pubKey.substring(0, 64), "hex");
        const finalX = Buffer.concat([Buffer.from(flag, 'hex'), x]);
        const finalXArray = new Uint8Array(finalX);
        // console.log("Public Key: \n"+ finalXArray);

        return finalXArray;
    } else {
        throw("Invalid public key length!" + pubKey.length);
    }
}

