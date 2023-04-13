import { agent } from './veramo/setup.js'
import * as fs from 'fs';

async function main() {
    const identifier = await agent.didManagerGetByAlias({ alias: 'molecule' })

    const verifiableCredential = await agent.createVerifiableCredential({
        credential: {
            issuer: { id: identifier.did },
            credentialSubject: {
                id: 'did:ethr:goerli:0x6566665656545465454664566465',
                readAccess: ["/vitaDAO/sub-17/file-23", "/vitaDAO/sub-17/file-18", "/vitaDAO/sub-17/file-119"]
            },
        },
        proofFormat: 'jwt',
    })
    console.log(`New credential created`)
    fs.writeFile ("verifiableCredential.json", JSON.stringify(verifiableCredential), function(err) {
            if (err) throw err;
            console.log('complete');
        }
    );
    console.log(JSON.stringify(verifiableCredential, null, 2))
}

main().catch(console.log)