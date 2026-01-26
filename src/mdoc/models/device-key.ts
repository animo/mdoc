import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type DeviceKeyStructure = EncodedCoseKeyStructure

export type DeviceKeyOptions = CoseKeyOptions

export class DeviceKey extends CoseKey {
  public static override fromEncodedStructure(encodedStructure: DeviceKeyStructure): DeviceKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new DeviceKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceKey {
    const structure = cborDecode<DeviceKeyStructure>(bytes, options)
    return DeviceKey.fromEncodedStructure(structure)
  }
}
