import fcl from '@onflow/fcl';
import elliptic from 'elliptic';
import {sha256} from 'js-sha256';
import { SHA3 } from 'sha3';

import {createSign, createHash, generateKeyPairSync} from 'node:crypto';
import * as eccrypto from 'eccrypto';

import fs from 'fs';
import path from 'path';


fcl.config().put('accessNode.api', 'http://127.0.0.1:8888');
fcl.config().put('0xProfile', '0xf8d6e0586b0a20c7');
fcl.config().put('Profile', 'f8d6e0586b0a20c7');

// Get block at height (uses builder function)
// const response = await fcl.send([fcl.getBlock(), fcl.atBlockHeight(1)]).then(fcl.decode);
// console.log(response);

// const account = await fcl.account("0xf8d6e0586b0a20c7");
// console.log(fcl.sansPrefix(account.address));
// console.log(fcl.withPrefix(account.address));

export class FlowService {
    constructor(address, privateKey, keyId, hashFun, curveName) {
        this.signerFlowAddress = address;// signer address 
        this.signerPrivateKeyHex = privateKey;// signer private key
        this.signerAccountIndex = keyId;// singer key index
        this.ec = new elliptic.ec(curveName);
        this.hashFunc = hashFun;
    }

    executeScripts = async ({ script, args }) => {
        const response = await fcl.send([fcl.script`${script}`, fcl.args(args)]);
        return await fcl.decode(response);
    }

    sendTx = async ({
        transaction,
        args,
    }) => {
        const response = await fcl.send([
          fcl.transaction`
            ${transaction}
          `,
          fcl.args(args),
          fcl.proposer(this.authzFn),
          fcl.authorizations([this.authzFn]),
          fcl.payer(this.authzFn),
          fcl.limit(9999)
        ]);
    
        return response;
    };

    authzFn = async (txAccount) => {
        const user = await fcl.account(this.signerFlowAddress);
        const key = user.keys[this.signerAccountIndex];

        const pk = this.signerPrivateKeyHex;
        
        return  {
            ...txAccount,
            tempId: `${user.address}-${key.index}`,
            addr: fcl.sansPrefix(user.address),
            keyId: Number(key.index),
            signingFunction: async(signable) => {
                return {
                addr: fcl.withPrefix(user.address),
                keyId: Number(key.index),
                signature: this.sign2string(signable.message)
                }
            }
        }
    }

    sign2string = (msg) => {
        const key = this.ec.keyFromPrivate(Buffer.from(this.signerPrivateKeyHex, 'hex'));
        const sig = key.sign(this.hashFunc(msg));
        const n = 32;
        const r = sig.r.toArrayLike(Buffer, 'be', n);
        const s = sig.s.toArrayLike(Buffer, 'be', n);
        return Buffer.concat([r, s]).toString('hex');
    };

    sign2buffer = (msg) => {
        const key = this.ec.keyFromPrivate(Buffer.from(this.signerPrivateKeyHex, 'hex'));
        const sig = key.sign(this.hashFunc(msg));
        const n = 32;
        const r = sig.r.toArrayLike(Buffer, 'be', n);
        const s = sig.s.toArrayLike(Buffer, 'be', n);
        return Buffer.concat([r, s]);
    };
}

async function createSubmittion() {
    const fService = new FlowService();

    const script = fs.readFileSync(
        path.join(
            process.cwd(),
            '../scripts/addressTest.cdc'
        ),
        'utf8'
    );
    
    const response = await fService.executeScripts(script, []);
    console.log(response);
}

const ec = new elliptic.ec('p256');

const sha3_256FromString = (msg) => {
    const sha = new SHA3(256);
    sha.update(Buffer.from(msg, 'utf8'));
    return sha.digest();
};

const sha3_256FromBytes = (msgBytes) => {
    const sha = new SHA3(256);
    sha.update(msgBytes);
    return sha.digest();
}

function signWithKey(msg) {

    const key = ec.keyFromPrivate(Buffer.from("69e7e51ead557351ade7a575e947c4d4bd19dd8a6cdf00c51f9c7f6f721b72dc", 'hex'));
    const sig = key.sign(sha3_256Hash(msg));
    const n = 32;
    const r = sig.r.toArrayLike(Buffer, 'be', n);
    const s = sig.s.toArrayLike(Buffer, 'be', n);
    console.log(sig.recoveryParam);
    return Buffer.concat([r, s]).toString('hex');
};

async function testSignature() {
    
    const fService = new FlowService("0xf8d6e0586b0a20c7", "69e7e51ead557351ade7a575e947c4d4bd19dd8a6cdf00c51f9c7f6f721b72dc", 0, sha3_256FromString, "p256");

    const signed = fService.sign2string('hello nika');
    console.log(signed);
}

async function exampleHash() {
    const msg2sign = "hello nika";
    console.log(sha256(msg2sign));
    console.log(sha3_256FromString(msg2sign).toString('hex'));
    console.log(sha3_256FromBytes(Buffer.from(msg2sign, 'utf8')).toString('hex'));
}

async function signatureWithCrypto() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });

    const privateKeyStr = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    console.log(privateKeyStr);

    const sign = createSign('SHA3-256');
    sign.update('hello nika');
    sign.end();
    const signature = sign.sign(privateKey, 'hex');

    console.log(signature);
}

async function signWithEccrypto() {
    const privateKey = Buffer.from('69e7e51ead557351ade7a575e947c4d4bd19dd8a6cdf00c51f9c7f6f721b72dc', 'hex');

    var msg = createHash("SHA3-256").update('hello nika').digest();
    // console.log(msg.toString('hex'));

    const signature = await eccrypto.sign(privateKey, msg);
    console.log(signature.toString('hex'));
}

// export default FlowService;

export async function settlement(response) {
    try {
        let rst = fcl.tx(response.transactionId);
        let rstData = await rst.onceSealed()
        console.log(rstData);
        // console.log(await rst.onceFinalized());
        return {
            status: true,
            data: rstData
        }
    } catch (error) {
        console.log(error);
        return {
            status: false,
            data: error
        }
    }
}

export async function sendTransaction({flowService, tx_path, args}) {
    const tras = fs.readFileSync(
        path.join(
            process.cwd(),
            tx_path
        ),
        'utf8'
    );

    return await flowService.sendTx({
        transaction: tras,
        args: args
    });
}

export async function execScripts({flowService, script_path, args}) {
    const script = fs.readFileSync(
        path.join(
            process.cwd(),
            script_path
        ),
        'utf8'
    );

    return await flowService.executeScripts({
        script: script,
        args: args
    });
}
