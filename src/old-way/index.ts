import fs from "fs";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import {DataSource} from "typeorm";
import {DIDStore, Entities, KeyStore, migrations, PrivateKeyStore} from "@veramo/data-store";
import {
    createAgent,
    ICredentialPlugin,
    IDataStore,
    IDataStoreORM,
    IDIDManager,
    IKeyManager,
    IResolver
} from "@veramo/core";
import {KeyManager} from "@veramo/key-manager";
import {KeyManagementSystem, SecretBox} from "@veramo/kms-local";
import {DIDManager} from "@veramo/did-manager";
import {EthrDIDProvider} from "@veramo/did-provider-ethr";
import {DIDResolverPlugin} from "@veramo/did-resolver";
import {Resolver} from "did-resolver";
import {getResolver as ethrDidResolver} from "ethr-did-resolver/lib/resolver";
import {getResolver as webDidResolver} from "web-did-resolver";
import {CredentialPlugin} from "@veramo/credential-w3c";


dotenv.config();
// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = 'database.sqlite'

// You will need to get a project ID from infura https://www.infura.io
const INFURA_PROJECT_ID = process.env.INFURA_PROJECT_ID

// This will be the secret key for the KMS
const KMS_SECRET_KEY = process.env.KMS_SECRET_KEY

const dbConnection = new DataSource({
    type: 'sqlite',
    database: DATABASE_FILE,
    synchronize: false,
    migrations,
    migrationsRun: true,
    logging: ['error', 'info', 'warn'],
    entities: Entities,
}).initialize()

const agent = createAgent<
    IDIDManager & IKeyManager & IDataStore & IDataStoreORM & IResolver & ICredentialPlugin
>({
    plugins: [
        new KeyManager({
            store: new KeyStore(dbConnection),
            kms: {
                local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY!))),
            },
        }),
        new DIDManager({
            store: new DIDStore(dbConnection),
            defaultProvider: 'did:ethr:goerli',
            providers: {
                'did:ethr:goerli': new EthrDIDProvider({
                    defaultKms: 'local',
                    network: 'goerli',
                    rpcUrl: 'https://goerli.infura.io/v3/' + INFURA_PROJECT_ID,
                }),
            },
        }),
        new DIDResolverPlugin({
            resolver: new Resolver({
                ...ethrDidResolver({ infuraProjectId: INFURA_PROJECT_ID }),
                ...webDidResolver(),
            }),
        }),
        new CredentialPlugin(),
    ],
})
const createIdentifier = async () => {
    const identifier = await agent.didManagerCreate({ alias: 'molecule.to' })
    console.log(`New identifier created`)
    console.log(JSON.stringify(identifier, null, 2))
}
const createCredential = async () => {
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
const verifyCredential = async () => {
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

const main = async () => {
    await createCredential()
    await verifyCredential()
}

main()