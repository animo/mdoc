import { type CborDecodeOptions, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpDcApiDraft24HandoverInfo } from './oid4vp-dc-api-draft24-handover-info'
import type { Oid4vpDcApiHandoverInfo } from './oid4vp-dc-api-handover-info'

export type Oid4vpDcApiHandoverStructure = [string, Uint8Array]

export type Oid4vpDcApiHandoverOptions = {
  oid4vpDcApiHandoverInfo?: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo
  oid4vpDcApiHandoverInfoHash?: Uint8Array
}

export class Oid4vpDcApiHandover extends Handover {
  public oid4vpDcApiHandoverInfo?: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo
  public oid4vpDcApiHandoverInfoHash?: Uint8Array

  public constructor(options: Oid4vpDcApiHandoverOptions) {
    super()
    this.oid4vpDcApiHandoverInfo = options.oid4vpDcApiHandoverInfo
    this.oid4vpDcApiHandoverInfoHash = options.oid4vpDcApiHandoverInfoHash
  }

  public async prepare(ctx: Pick<MdocContext, 'crypto'>) {
    if (!this.oid4vpDcApiHandoverInfo && !this.oid4vpDcApiHandoverInfoHash) {
      throw new Error(`Either the 'oid4vpDcApiHandoverInfo' or 'oid4vpDcApiHandoverInfoHash' must be set`)
    }

    if (this.oid4vpDcApiHandoverInfo) {
      this.oid4vpDcApiHandoverInfoHash = await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: this.oid4vpDcApiHandoverInfo.encode(),
      })
    }
  }

  public encodedStructure(): Oid4vpDcApiHandoverStructure {
    if (!this.oid4vpDcApiHandoverInfoHash) {
      throw new Error('Call `prepare` first to create the hash over the handover info')
    }

    return ['OpenID4VPDCAPIHandover', this.oid4vpDcApiHandoverInfoHash]
  }

  public static override fromEncodedStructure(encodedStructure: Oid4vpDcApiHandoverStructure): Oid4vpDcApiHandover {
    return new Oid4vpDcApiHandover({
      oid4vpDcApiHandoverInfoHash: encodedStructure[1],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpDcApiHandover {
    const structure = cborDecode<Oid4vpDcApiHandoverStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Oid4vpDcApiHandover.fromEncodedStructure(structure)
  }

  public static isCorrectHandover(structure: unknown): structure is Oid4vpDcApiHandoverStructure {
    return Array.isArray(structure) && structure[0] === 'OpenID4VPDCAPIHandover'
  }
}
