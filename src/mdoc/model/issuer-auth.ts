import { type CborDecodeOptions, cborDecode } from '../../cbor/index.js'
import type { X509Context } from '../../context.js'
import { CosePayloadMustBeDefined } from '../../cose/error.js'
import { Sign1, type Sign1Options, type Sign1Structure } from '../../cose/sign1.js'
import { Mso } from './mso.js'

export type IssuerAuthStructure = Sign1Structure
export type IssuerAuthOptions = Sign1Options

/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export class IssuerAuth extends Sign1 {
  public get mso(): Mso {
    if (!this.payload) {
      throw new CosePayloadMustBeDefined()
    }

    const mso = Mso.decode(this.payload)

    // @todo this should happen in the `Mso.decode` method
    // const mapValidityInfo = (validityInfo?: Map<string, Uint8Array>) => {
    //   if (!validityInfo) {
    //     return validityInfo
    //   }
    //   return Object.fromEntries(
    //     [...validityInfo.entries()].map(([key, value]) => {
    //       return [key, value instanceof Uint8Array ? cborDecode(value) : value]
    //     })
    //   )
    // }

    // const result: MSO = {
    //   ...decodedEntries,
    //   validityInfo: mapValidityInfo(decodedEntries.validityInfo),
    //   validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : undefined,
    //   deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : undefined,
    // }
    // this.#decodedPayload = result
    // return result
    return mso
  }

  /**
   *
   * @todo the original method seems very weird here...
   *
   */
  public get certificateChain() {
    return [] as Array<Uint8Array>
  }

  public get certificate() {
    return this.certificateChain[0]
  }

  public getIssuingCountry(ctx: { x509: X509Context }) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0]

    return countryName
  }

  public getIssuingStateOrProvince(ctx: { x509: X509Context }) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0]

    return stateOrProvince
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    const data = cborDecode<IssuerAuthStructure>(bytes, options)

    return new IssuerAuth({
      protectedHeaders: data[0] as Uint8Array,
      unprotectedHeaders: data[1] as Map<unknown, unknown>,
      payload: data[2] as Uint8Array,
      signature: data[3] as Uint8Array,
    })
  }
}
