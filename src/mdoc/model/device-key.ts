import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { CoseKey, type CoseKeyOptions, type CoseKeyStructure } from '../../cose/key'

export type DeviceKeyStructure = CoseKeyStructure

export type DeviceKeyOptions = CoseKeyOptions

export class DeviceKey extends CoseKey {
  public static override fromEncodedStructure(encodedStructure: DeviceKeyStructure | Map<unknown, unknown>): DeviceKey {
    const key = CoseKey.fromEncodedStructure(encodedStructure)
    return new DeviceKey(key)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceKey {
    const structure = cborDecode<DeviceKeyStructure>(bytes, options)
    return DeviceKey.fromEncodedStructure(structure)
  }
}
