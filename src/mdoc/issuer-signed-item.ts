import type { MdocContext, X509Context } from '../c-mdoc.js'
import { DataItem } from '../cbor/data-item.js'
import { cborEncode } from '../cbor/index.js'
import { areEqualUint8Array } from '../u-uint8-array.js'
import type IssuerAuth from './model/issuer-auth.js'
import type { DigestAlgorithm } from './model/types.js'

export const MDL_NAMESPACE = 'org.iso.18013.5.1'

const supportedDigestAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512']

export type IssuerSignedDataItem = DataItem<Map<keyof IssuerSignedItem, unknown>>

export class IssuerSignedItem {
  readonly #dataItem: IssuerSignedDataItem
  #isValid: boolean | undefined

  constructor(dataItem: IssuerSignedDataItem) {
    this.#dataItem = dataItem
  }

  public encode() {
    return this.#dataItem.buffer
  }

  public get dataItem() {
    return this.#dataItem
  }

  private get decodedData() {
    if (!this.#dataItem.data.has('digestID')) {
      throw new Error('Invalid data item')
    }
    return this.#dataItem.data
  }

  public get digestID(): number {
    return this.decodedData.get('digestID') as number
  }

  public get random(): Uint8Array {
    return this.decodedData.get('random') as Uint8Array
  }

  public get elementIdentifier(): string {
    return this.decodedData.get('elementIdentifier') as string
  }

  public get elementValue(): unknown {
    return this.decodedData.get('elementValue')
  }

  public async calculateDigest(alg: DigestAlgorithm, ctx: { crypto: MdocContext['crypto'] }) {
    const bytes = cborEncode(this.#dataItem)
    const result = await ctx.crypto.digest({ digestAlgorithm: alg, bytes })
    return result
  }

  public async isValid(
    nameSpace: string,
    { decodedPayload: { valueDigests, digestAlgorithm } }: IssuerAuth,
    ctx: { crypto: MdocContext['crypto'] }
  ): Promise<boolean> {
    if (typeof this.#isValid !== 'undefined') {
      return this.#isValid
    }
    if (!supportedDigestAlgorithms.includes(digestAlgorithm)) {
      this.#isValid = false
      return false
    }
    const digest = await this.calculateDigest(digestAlgorithm, ctx)
    const digests = valueDigests?.get(nameSpace)
    if (typeof digests === 'undefined') {
      return false
    }
    const expectedDigest = digests.get(this.digestID)
    this.#isValid = expectedDigest && areEqualUint8Array(digest, expectedDigest)
    return Boolean(this.#isValid)
  }

  public matchCertificate(nameSpace: string, issuerAuth: IssuerAuth, ctx: { x509: X509Context }): boolean | undefined {
    if (nameSpace !== MDL_NAMESPACE) {
      return undefined
    }

    const issuingCountry = issuerAuth.getIssuingCountry(ctx)
    const issuingStateOrProvince = issuerAuth.getIssuingStateOrProvince(ctx)

    if (this.elementIdentifier === 'issuing_country') {
      return issuingCountry === this.elementValue
    }
    if (this.elementIdentifier === 'issuing_jurisdiction') {
      return issuingStateOrProvince === this.elementValue
    }
    return undefined
  }

  public static create(
    digestID: number,
    elementIdentifier: string,
    elementValue: unknown,
    ctx: { crypto: MdocContext['crypto'] }
  ): IssuerSignedItem {
    const random = ctx?.crypto.random(32)
    const dataItem: IssuerSignedDataItem = DataItem.fromData(
      new Map([
        ['digestID', digestID],
        ['elementIdentifier', elementIdentifier],
        ['elementValue', elementValue],
        ['random', random],
      ])
    )
    return new IssuerSignedItem(dataItem)
  }
}
