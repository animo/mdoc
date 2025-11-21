import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { Handover } from './handover'

export type NfcHandoverStructure = [Uint8Array, Uint8Array | null]

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage?: Uint8Array
}

export class NfcHandover extends Handover {
  public selectMessage: Uint8Array
  public requestMessage?: Uint8Array

  public constructor(options: NfcHandoverOptions) {
    super()
    this.selectMessage = options.selectMessage
    this.requestMessage = options.requestMessage
  }

  public encodedStructure(): NfcHandoverStructure {
    return [this.selectMessage, this.requestMessage ?? null]
  }

  public static override fromEncodedStructure(encodedStructure: NfcHandoverStructure): NfcHandover {
    return new NfcHandover({
      selectMessage: encodedStructure[0],
      requestMessage: encodedStructure[1] ?? undefined,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): NfcHandover {
    const structure = cborDecode<NfcHandoverStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return NfcHandover.fromEncodedStructure(structure)
  }

  public static isCorrectHandover(structure: unknown): structure is NfcHandoverStructure {
    return (
      Array.isArray(structure) &&
      structure[0] instanceof Uint8Array &&
      (structure[1] instanceof Uint8Array || structure[1] === null)
    )
  }
}
