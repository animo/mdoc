import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { compareBytes } from '../../utils'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

export type IssuerSignedItemStructure = {
  digestID: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export class IssuerSignedItem extends CborStructure {
  public digestId: number
  public random: Uint8Array
  public elementIdentifier: DataElementIdentifier
  public elementValue: DataElementValue

  public constructor(options: IssuerSignedItemOptions) {
    super()
    this.digestId = options.digestId
    this.random = options.random
    this.elementIdentifier = options.elementIdentifier
    this.elementValue = options.elementValue
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
    return {
      digestID: this.digestId,
      random: this.random,
      elementIdentifier: this.elementIdentifier,
      elementValue: this.elementValue,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: IssuerSignedItemStructure | Map<unknown, unknown>
  ): IssuerSignedItem {
    let structure = encodedStructure as IssuerSignedItemStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as IssuerSignedItemStructure
    }

    // Fix for driving_privileges
    if (structure.elementIdentifier === 'driving_privileges') {
      structure.elementValue = (structure.elementValue as Array<Map<unknown, unknown>>).map((ev) =>
        Object.fromEntries(ev.entries())
      )
    }

    return new IssuerSignedItem({
      digestId: structure.digestID,
      random: structure.random,
      elementIdentifier: structure.elementIdentifier,
      elementValue: structure.elementValue,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): IssuerSignedItem {
    const structure = cborDecode<IssuerSignedItemStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return IssuerSignedItem.fromEncodedStructure(structure)
  }
}
