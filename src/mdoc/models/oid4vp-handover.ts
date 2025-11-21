import { type CborDecodeOptions, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpHandoverInfo } from './oid4vp-handover-info'

export type Oid4vpHandoverStructure = [string, Uint8Array]

export type Oid4vpHandoverOptions = {
  oid4vpHandoverInfo?: Oid4vpHandoverInfo
  oid4vpHandoverInfoHash?: Uint8Array
}

export class Oid4vpHandover extends Handover {
  public oid4vpHandoverInfo?: Oid4vpHandoverInfo
  public oid4vpHandoverInfoHash?: Uint8Array

  public constructor(options: Oid4vpHandoverOptions) {
    super()
    this.oid4vpHandoverInfo = options.oid4vpHandoverInfo
    this.oid4vpHandoverInfoHash = options.oid4vpHandoverInfoHash
  }

  public async prepare(ctx: Pick<MdocContext, 'crypto'>) {
    if (!this.oid4vpHandoverInfo && !this.oid4vpHandoverInfoHash) {
      throw new Error(`Either the 'oid4vpHandoverInfo' or 'oid4vpHandoverInfoHash' must be set`)
    }

    if (this.oid4vpHandoverInfo) {
      this.oid4vpHandoverInfoHash = await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: this.oid4vpHandoverInfo.encode(),
      })
    }
  }

  public encodedStructure(): Oid4vpHandoverStructure {
    if (!this.oid4vpHandoverInfoHash) {
      throw new Error('Call `prepare` first to create the hash over the handover info')
    }

    return ['OpenID4VPHandover', this.oid4vpHandoverInfoHash]
  }

  public static override fromEncodedStructure(encodedStructure: Oid4vpHandoverStructure): Oid4vpHandover {
    return new Oid4vpHandover({
      oid4vpHandoverInfoHash: encodedStructure[1],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpHandover {
    const structure = cborDecode<Oid4vpHandoverStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Oid4vpHandover.fromEncodedStructure(structure)
  }

  public static isCorrectHandover(structure: unknown): structure is Oid4vpHandoverStructure {
    return Array.isArray(structure) && structure[0] === 'OpenID4VPHandover' && structure[1] instanceof Uint8Array
  }
}
