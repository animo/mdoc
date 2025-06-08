import { mdocContext } from '../../tests/context'
import { cborDecode, cborEncode } from '../cbor'
import {
  type CoseKey,
  Mac0,
  type Mac0Options,
  type Mac0Structure,
  Sign1,
  type Sign1Options,
  type Sign1Structure,
} from '../cose'

type Header = {
  protected?: Record<string, unknown>
  unprotected?: Record<string, unknown>
}

type CWTOptions = {
  type: 'sign1' | 'mac0' | 'encrypt0'
  key: CoseKey
}

interface CWTVerifyOptions {
  type: 'sign1' | 'mac0'
  token: Uint8Array
  key?: CoseKey
}

enum CwtStandardClaims {
  Iss = 1,
  Sub = 2,
  Aud = 3,
  Exp = 4,
  Nbf = 5,
  Iat = 6,
  Cti = 7,
}

export class CWT {
  private claimsSet: Record<string, unknown> = {}
  private headers: Header = {}

  setIss(iss: string): void {
    this.claimsSet[CwtStandardClaims.Iss] = iss
  }
  setSub(sub: string): void {
    this.claimsSet[CwtStandardClaims.Sub] = sub
  }
  setAud(aud: string): void {
    this.claimsSet[CwtStandardClaims.Aud] = aud
  }
  setExp(exp: number): void {
    this.claimsSet[CwtStandardClaims.Exp] = exp
  }
  setNbf(nbf: number): void {
    this.claimsSet[CwtStandardClaims.Nbf] = nbf
  }
  setIat(iat: number): void {
    this.claimsSet[CwtStandardClaims.Iat] = iat
  }
  setCti(cti: Uint8Array): void {
    this.claimsSet[CwtStandardClaims.Cti] = cti
  }

  setClaims(claims: Record<string, unknown>): void {
    this.claimsSet = claims
  }

  setHeaders(headers: Header): void {
    this.headers = headers
  }

  async create({ type, key }: CWTOptions): Promise<Sign1Structure | Mac0Structure> {
    switch (type) {
      case 'sign1': {
        const sign1Options: Sign1Options = {
          protectedHeaders: this.headers.protected ? cborEncode(this.headers.protected) : undefined,
          unprotectedHeaders: this.headers.unprotected ? new Map(Object.entries(this.headers.unprotected)) : undefined,
          payload: this.claimsSet ? cborEncode(this.claimsSet) : null,
        }

        const sign1 = new Sign1(sign1Options)
        await sign1.addSignature({ signingKey: key }, { cose: mdocContext.cose })
        return sign1.encodedStructure()
      }
      case 'mac0': {
        if (!this.headers.protected || !this.headers.unprotected) {
          throw new Error('Protected and unprotected headers must be defined for MAC0')
        }
        const mac0Options: Mac0Options = {
          protectedHeaders: this.headers.protected ? cborEncode(this.headers.protected) : undefined,
          unprotectedHeaders: this.headers.unprotected ? new Map(Object.entries(this.headers.unprotected)) : undefined,
          payload: this.claimsSet ? cborEncode(this.claimsSet) : null,
        }

        const mac0 = new Mac0(mac0Options)
        // await mac0.addTag({ privateKey: key, ephemeralKey: key, sessionTranscript: new SessionTranscript({ handover: new QrHandover() }) }, mdocContext);
        // return mac0.encodedStructure();
        throw new Error('MAC0 is not yet implemented')
      }
      case 'encrypt0':
        throw new Error('Encrypt0 is not yet implemented')
      default:
        throw new Error('Unsupported CWT type')
    }
  }

  static async verify({ type, token, key }: CWTVerifyOptions): Promise<boolean> {
    const cwt = cborDecode(token) as Sign1Structure | Mac0Structure
    switch (type) {
      case 'sign1': {
        const sign1Options: Sign1Options = {
          protectedHeaders: cwt[0],
          unprotectedHeaders: cwt[1],
          payload: cwt[2],
          signature: cwt[3],
        }
        const sign1 = new Sign1(sign1Options)
        return await sign1.verify({ key }, mdocContext)
      }
      default:
        throw new Error('Unsupported CWT type for verification')
    }
  }
}
