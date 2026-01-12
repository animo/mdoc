import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { compareBytes } from '../../utils'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

export type IssuerSignedItemStructure = Map<
  'digestID' | 'random' | 'elementIdentifier' | 'elementValue',
  number | Uint8Array | DataElementIdentifier | DataElementValue
>

export type IssuerSignedItemOptions =
  | {
      digestId: number
      random: Uint8Array
      elementIdentifier: DataElementIdentifier
      elementValue: DataElementValue
    }
  | { issuerSignedItemStructure: IssuerSignedItemStructure }

export class IssuerSignedItem extends CborStructure {
  #issuerSignedItemStructure: IssuerSignedItemStructure

  public constructor(options: IssuerSignedItemOptions) {
    super()

    // We want to keep the order as is used by the signed mdoc
    // to ensure we generate the same digest
    if ('issuerSignedItemStructure' in options) {
      this.#issuerSignedItemStructure = options.issuerSignedItemStructure
    } else {
      this.#issuerSignedItemStructure = new Map([
        ['digestID', options.digestId],
        ['random', options.random],
        ['elementIdentifier', options.elementIdentifier],
        ['elementValue', options.elementValue],
      ])
    }
  }

  public get random(): Uint8Array {
    return this.#issuerSignedItemStructure.get('random') as Uint8Array
  }
  public get elementIdentifier(): DataElementIdentifier {
    return this.#issuerSignedItemStructure.get('elementIdentifier') as DataElementIdentifier
  }

  public get elementValue(): DataElementValue {
    return this.#issuerSignedItemStructure.get('elementValue') as DataElementValue
  }

  public get digestId(): number {
    return this.#issuerSignedItemStructure.get('digestID') as number
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

  public static override fromEncodedStructure(
    encodedStructure: IssuerSignedItemStructure | Map<unknown, unknown>
  ): IssuerSignedItem {
    return new IssuerSignedItem({
      issuerSignedItemStructure: encodedStructure as IssuerSignedItemStructure,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): IssuerSignedItem {
    const structure = cborDecode<IssuerSignedItemStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return IssuerSignedItem.fromEncodedStructure(structure)
  }
}
