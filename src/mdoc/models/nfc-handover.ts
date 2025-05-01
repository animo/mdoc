import { CborStructure } from '../../cbor'

export type NfcHandoverStructure = [Uint8Array, Uint8Array | null]

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage?: Uint8Array
}

export class NfcHandover extends CborStructure {
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
}
