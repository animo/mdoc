import { cborEncode } from '../../cbor'

export interface Handover {
  encode(): Uint8Array
}

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage: Uint8Array | null
}

export class NfcHandover implements Handover {
  public selectMessage: Uint8Array
  public requestMessage: Uint8Array | null

  public constructor(options: NfcHandover) {
    this.selectMessage = options.selectMessage
    this.requestMessage = options.requestMessage
  }

  public encode() {
    return cborEncode([this.selectMessage, this.requestMessage])
  }
}

export class QrHandover implements Handover {
  public encode() {
    return cborEncode(null)
  }
}
