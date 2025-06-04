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
    ISS = 1,
    SUB = 2,
    AUD = 3,
    EXP = 4,
    NBF = 5,
    IAT = 6,
    CTI = 7
}

export class CWT {
    private claimsSet: Record<string, any> = {};
    private headers: Header = {};

    setIss(iss: string): void {
        this.claimsSet[CwtStandardClaims.ISS] = iss;
    }
    setSub(sub: string): void {
        this.claimsSet[CwtStandardClaims.SUB] = sub;
    }
    setAud(aud: string): void {
        this.claimsSet[CwtStandardClaims.AUD] = aud;
    }
    setExp(exp: number): void {
        this.claimsSet[CwtStandardClaims.EXP] = exp;
    }
    setNbf(nbf: number): void {
        this.claimsSet[CwtStandardClaims.NBF] = nbf;
    }
    setIat(iat: number): void {
        this.claimsSet[CwtStandardClaims.IAT] = iat;
    }
    setCti(cti: Uint8Array): void {
        this.claimsSet[CwtStandardClaims.CTI] = cti;
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
