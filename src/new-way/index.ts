import * as ed25519 from '@transmute/did-key-ed25519';
import {Ed25519KeyPair} from '@transmute/did-key-ed25519';
import {JWS} from '@transmute/jose-ld';
import {Ed25519VerificationKey2018} from "@transmute/ed25519-key-pair/src/types/Ed25519VerificationKey2018";
import {JsonWebKey2020} from "@transmute/ed25519-key-pair/src/types/JsonWebKey2020";

const JWA_ALG = 'EdDSA';

type VerifiableCredential = {
    credential: {
        issuer: { id: string },
        credentialSubject: {
            id: string,
            readAccess: string[]
        }
    },
    proofFormat: string,
    signature?: string
}
const generateIssuer = async (): Promise<any> => {
    const k = await Ed25519KeyPair.generate({
        secureRandom: () => {
            return Buffer.from(
                '4e61bc1918ea6a47ae3307331be7798196a1a8e7cfe4b6e8f7c9a5f36017d929',
                'hex'
            );
        },
    });
    const exportedKeyPair: JsonWebKey2020 | Ed25519VerificationKey2018 = await k.export({
        type: 'Ed25519VerificationKey2018',
        privateKey: true,
    });
    return k;
}

const verifyCredential = async (issuer: any, credential: VerifiableCredential) => {
    const signature: string = credential.signature!;
    delete credential.signature;
    const signer = JWS.createSigner(issuer.signer('EdDsa'), JWA_ALG);
    const message = Uint8Array.from(Buffer.from(JSON.stringify(credential)));
    const createdSignature = await signer.sign({data: message});
    if (signature !== createdSignature) return false;
    const verifier = JWS.createVerifier(issuer.verifier('EdDsa'), JWA_ALG);
    return await verifier.verify({
        signature,
    });
}

const generateVerifiableCredential = async (issuer: any) => {
    const verifiableCredential: VerifiableCredential = {
        credential: {
            issuer: { id: issuer.id },
            credentialSubject: {
                id: 'did:key:0x6566665656545465454664566465',
                readAccess: ["/vitaDAO/sub-17/file-23", "/vitaDAO/sub-17/file-18", "/vitaDAO/sub-17/file-119"]
            },
        },
        proofFormat: 'signature',
    };
    const signer = JWS.createSigner(issuer.signer('EdDsa'), JWA_ALG);
    const message = Uint8Array.from(Buffer.from(JSON.stringify(verifiableCredential)));
    verifiableCredential.signature = await signer.sign({data: message});
    return verifiableCredential
}

export const resolveDID = async (did: string) => {
    return  await ed25519.resolve(
        did,
        { accept: 'application/did+json' }
    );
}

const main = async () => {
    // @ts-ignore
    const issuer: { type: string, id: string, controller: string, publicKey: Uint8Array, privateKey: Uint8Array }  = await generateIssuer();
    const verifiableCredential = await generateVerifiableCredential(issuer);
    console.log(verifiableCredential);
    const credentialVerified = await verifyCredential(issuer, verifiableCredential);
    console.log(credentialVerified)
}

main()