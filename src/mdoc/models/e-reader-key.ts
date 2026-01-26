import { type CborDecodeOptions, type CborEncodeOptions, cborDecode, cborEncode, DataItem } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type EReaderKeyStructure = EncodedCoseKeyStructure

export type EReaderKeyOptions = CoseKeyOptions

export class EReaderKey extends CoseKey {
  /**
   * Original CBOR bytes (preserved when decoding to ensure encode() returns identical bytes)
   */
  #rawBytes?: Uint8Array

  public override encode(options?: CborEncodeOptions): Uint8Array {
    if (this.#rawBytes) {
      if (options?.asDataItem) {
        return cborEncode(new DataItem({ buffer: this.#rawBytes }))
      }
      return this.#rawBytes
    }
    return super.encode(options)
  }

  public static override fromEncodedStructure(encodedStructure: EReaderKeyStructure): EReaderKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new EReaderKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EReaderKey {
    const structure = cborDecode<EReaderKeyStructure>(bytes, options)
    const key = EReaderKey.fromEncodedStructure(structure)
    key.#rawBytes = bytes
    return key
  }
}
