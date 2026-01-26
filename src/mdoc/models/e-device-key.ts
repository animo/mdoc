import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type EDeviceKeyStructure = EncodedCoseKeyStructure

export type EDeviceKeyOptions = CoseKeyOptions

export class EDeviceKey extends CoseKey {
  public static override fromEncodedStructure(encodedStructure: EDeviceKeyStructure): EDeviceKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new EDeviceKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EDeviceKey {
    const structure = cborDecode<EDeviceKeyStructure>(bytes, options)
    return EDeviceKey.fromEncodedStructure(structure)
  }
}
