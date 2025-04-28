import { type CborDecodeOptions, DataItem, cborDecode } from '../../cbor/index.js'
import type { X509Context } from '../../context.js'
import { CosePayloadInvalidStructure, CosePayloadMustBeDefined } from '../../cose/error.js'
import { Sign1, type Sign1Options, type Sign1Structure } from '../../cose/sign1.js'
import { MobileSecurityObject, type MobileSecurityObjectStructure } from './mobile-security-object.js'

export type IssuerAuthStructure = Sign1Structure
export type IssuerAuthOptions = Sign1Options

export class IssuerAuth extends Sign1 {
  public get mso(): MobileSecurityObject {
    if (!this.payload) {
      throw new CosePayloadMustBeDefined()
    }

    const dataItem = cborDecode<DataItem<MobileSecurityObjectStructure>>(this.payload)

    if (!(dataItem instanceof DataItem)) {
      throw new CosePayloadInvalidStructure()
    }

    const mso = MobileSecurityObject.decode(dataItem.buffer)

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
    return IssuerAuth.fromEncodedStructure(data)
  }

  public static override fromEncodedStructure(encodedStructure: IssuerAuthStructure): IssuerAuth {
    return new IssuerAuth({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }
}
