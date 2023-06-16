import fcl from '@onflow/fcl';
import elliptic from 'elliptic';
import fs from 'fs';
import path from 'path';
import process from 'process';

// const defaultFile = await import("./config/default.json", {
//     assert: {
//       type: "json"
//     }
// });

const configure = JSON.parse(fs.readFileSync(path.join(process.cwd(),'./scaffold-flow/config/default.json')), 'utf8');
// console.log(configure);

fcl.config().put('accessNode.api', configure.accessNode);
fcl.config().put('0xProfile', configure.ownerAddress);
fcl.config().put('Profile', configure.ownerAddress);

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

// export default FlowService;
export async function settlement(response) {
    try {
        let rst = fcl.tx(response.transactionId);
        let rstData = await rst.onceSealed()
        // console.log(rstData);
        // console.log(await rst.onceFinalized());
        return {
            status: true,
            data: rstData
        }
    } catch (error) {
        // console.log(error);
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
