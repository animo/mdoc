import { CborStructure } from '../../cbor'

export type NfcOptionsStructure = {
  0: number
  1: number
}

export type NfcOptionsOptions = {
  maxLenCommandDataField: number
  maxLenResponseDataField: number
}

export class NfcOptions extends CborStructure {
  public maxLenCommandDataField: number
  public maxLenResponseDataField: number

  public constructor(options: NfcOptionsOptions) {
    super()
    this.maxLenCommandDataField = options.maxLenCommandDataField
    this.maxLenResponseDataField = options.maxLenResponseDataField
  }

  public encodedStructure(): NfcOptionsStructure {
    return {
      0: this.maxLenCommandDataField,
      1: this.maxLenResponseDataField,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: NfcOptionsStructure | Map<number, unknown>
  ): NfcOptions {
    let structure = encodedStructure as NfcOptionsStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as NfcOptionsStructure
    }

    return new NfcOptions({
      maxLenCommandDataField: structure[0],
      maxLenResponseDataField: structure[1],
    })
  }
}
