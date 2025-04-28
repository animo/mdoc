import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type KeyInfoStructure = Map<number, unknown>
export type KeyInfoOptions = {
  keyInfo: Map<number, unknown>
}

export class KeyInfo extends CborStructure {
  public keyInfo: Map<number, unknown>

  public constructor(options: KeyInfoOptions) {
    super()
    this.keyInfo = options.keyInfo
  }

  public encodedStructure(): KeyInfoStructure {
    return this.keyInfo
  }

  public static override fromEncodedStructure(encodedStructure: KeyInfoStructure): KeyInfo {
    return new KeyInfo({ keyInfo: encodedStructure })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): KeyInfo {
    const structure = cborDecode<KeyInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return KeyInfo.fromEncodedStructure(structure)
  }
}
