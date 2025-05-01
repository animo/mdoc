import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type CoseKeyStructure } from '../../cose/key/key'

export type EDeviceKeyStructure = CoseKeyStructure

export type EDeviceKeyOptions = CoseKeyOptions

export class EDeviceKey extends CoseKey {
  public static override fromEncodedStructure(
    encodedStructure: EDeviceKeyStructure | Map<unknown, unknown>
  ): EDeviceKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new EDeviceKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EDeviceKey {
    const structure = cborDecode<Map<unknown, unknown>>(bytes, options)
    return EDeviceKey.fromEncodedStructure(structure)
  }
}
