import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type CoseKeyStructure } from '../../cose/key/key'

export type EReaderKeyStructure = CoseKeyStructure

export type EReaderKeyOptions = CoseKeyOptions

export class EReaderKey extends CoseKey {
  public static override fromEncodedStructure(
    encodedStructure: EReaderKeyStructure | Map<unknown, unknown>
  ): EReaderKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new EReaderKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EReaderKey {
    const structure = cborDecode<Map<unknown, unknown>>(bytes, options)
    return EReaderKey.fromEncodedStructure(structure)
  }
}
