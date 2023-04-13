import {agent} from './veramo/setup.js'
import * as fs from 'fs';
import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from "node:crypto";
async function main() {
    const vc = JSON.parse(fs.readFileSync('./verifiableCredential.json', 'utf-8'))
    const result = await agent.verifyCredential({
        credential: vc,
    })
    console.log(`Credential verified`, result.verified)
    if(result.verified) {
        const claims = {
            sub: vc.credentialSubject.id,
            access: vc.credentialSubject.readAccess,
            jti: crypto.randomBytes(64).toString("hex"),
            exp: Math.floor(Date.now() / 1000) + 45
        };
        const token = jwt.sign(claims, 'secretWord');
        console.log(token);
        const decoded = jwt.verify(token, 'secretWord');
        console.log(decoded)
    }
}

main().catch(console.log)