import { CoseKey, Mac0, Mac0Options, Mac0Structure, Sign1, Sign1Options, Sign1Structure } from '../cose';
import { mdocContext } from '../../tests/context';
import { cborEncode } from '../cbor';

type Header = {
    protected?: Record<string, any>;
    unprotected?: Record<string, any>;
};

type CWTOptions = {
    type: 'sign1' | 'mac0' | 'encrypt0';
    key: CoseKey;
};

enum CwtStandardClaims {
    Iss = 1,
    Sub = 2,
    Aud = 3,
    Exp = 4,
    Nbf = 5,
    Iat = 6,
    Cti = 7
}

export class CWT {
    private claimsSet: Record<string, any> = {};
    private headers: Header = {};

    setIss(iss: string): void {
        this.claimsSet[CwtStandardClaims.Iss] = iss;
    }
    setSub(sub: string): void {
        this.claimsSet[CwtStandardClaims.Sub] = sub;
    }
    setAud(aud: string): void {
        this.claimsSet[CwtStandardClaims.Aud] = aud;
    }
    setExp(exp: number): void {
        this.claimsSet[CwtStandardClaims.Exp] = exp;
    }
    setNbf(nbf: number): void {
        this.claimsSet[CwtStandardClaims.Nbf] = nbf;
    }
    setIat(iat: number): void {
        this.claimsSet[CwtStandardClaims.Iat] = iat;
    }
    setCti(cti: Uint8Array): void {
        this.claimsSet[CwtStandardClaims.Cti] = cti;
    }

    setClaims(claims: Record<string, any>): void {
        this.claimsSet = claims;
    }

    setHeaders(headers: Header): void {
        this.headers = headers;
    }

    async create({ type, key }: CWTOptions): Promise<Sign1Structure | Mac0Structure> {
        switch (type) {
            case 'sign1':
                const sign1Options: Sign1Options = {
                    protectedHeaders: this.headers.protected ? cborEncode(this.headers.protected) : undefined,
                    unprotectedHeaders: this.headers.unprotected ? new Map(Object.entries(this.headers.unprotected)) : undefined,
                    payload: this.claimsSet ? cborEncode(this.claimsSet) : null, // Need to encode this to binary format
                };

                const sign1 = new Sign1(sign1Options);
                await sign1.addSignature({ signingKey: key }, { cose: mdocContext.cose });
                return sign1.encodedStructure()
            case 'mac0':
                if (!this.headers.protected || !this.headers.unprotected) {
                    throw new Error('Protected and unprotected headers must be defined for MAC0');
                }
                const mac0Options: Mac0Options = {
                    protectedHeaders: this.headers.protected ? cborEncode(this.headers.protected) : undefined,
                    unprotectedHeaders: this.headers.unprotected ? new Map(Object.entries(this.headers.unprotected)) : undefined,
                    payload: this.claimsSet ? cborEncode(this.claimsSet) : null, // Need to encode this to binary format
                };

                const mac0 = new Mac0(mac0Options);
            // await mac0.addTag({ privateKey: key, ephemeralKey: key, sessionTranscript: new SessionTranscript({ handover: new QrHandover() }) }, mdocContext);
            // return mac0.encodedStructure();
            case 'encrypt0':
                throw new Error('Encrypt0 is not yet implemented');
            default:
                throw new Error('Unsupported CWT type');
        }
    }
}
