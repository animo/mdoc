import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { compareBytes } from '../../utils'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

export interface IssuerSignedItemStructure {
  digestID: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

// NOTE: Id vs ID above
export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export class IssuerSignedItem extends CborStructure {
  #issuerSignedItemStructure: IssuerSignedItemStructure

  private constructor(options: IssuerSignedItemStructure) {
    super()

    this.#issuerSignedItemStructure = options
  }

  public get random(): Uint8Array {
    return this.#issuerSignedItemStructure.random
  }
  public get elementIdentifier(): DataElementIdentifier {
    return this.#issuerSignedItemStructure.elementIdentifier
  }

  public get elementValue(): DataElementValue {
    return this.#issuerSignedItemStructure.elementValue
  }

  public get digestId(): number {
    return this.#issuerSignedItemStructure.digestID
  }

  public async isValid(namespace: Namespace, issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'crypto'>) {
    const digest = await ctx.crypto.digest({
      digestAlgorithm: issuerAuth.mobileSecurityObject.digestAlgorithm,
      bytes: this.encode({ asDataItem: true }),
    })

    const valueDigests = issuerAuth.mobileSecurityObject.valueDigests.valueDigests
    const digests = valueDigests.get(namespace)

    if (!digests) {
      return false
    }

    const expectedDigest = digests.get(this.digestId)

    return expectedDigest !== undefined && compareBytes(digest, expectedDigest)
  }

  public matchCertificate(issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'x509'>) {
    if (this.elementIdentifier === 'issuing_country') {
      return this.elementValue === issuerAuth.getIssuingCountry(ctx)
    }

    if (this.elementIdentifier === 'issuing_jurisdiction') {
      return this.elementValue === issuerAuth.getIssuingStateOrProvince(ctx)
    }

    return false
  }

  public encodedStructure(): IssuerSignedItemStructure {
    return this.#issuerSignedItemStructure
  }

  public static fromOptions(options: IssuerSignedItemOptions) {
    return new IssuerSignedItem({
      digestID: options.digestId,
      random: options.random,
      elementIdentifier: options.elementIdentifier,
      elementValue: options.elementValue,
    })
  }

  public static override fromEncodedStructure(
    encodedStructure: IssuerSignedItemStructure | Map<unknown, unknown>
  ): IssuerSignedItem {
    return new IssuerSignedItem(
      encodedStructure instanceof Map ? Object.fromEntries(encodedStructure.entries()) : encodedStructure
    )
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): IssuerSignedItem {
    const structure = cborDecode<IssuerSignedItemStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return IssuerSignedItem.fromEncodedStructure(structure)
  }
}
