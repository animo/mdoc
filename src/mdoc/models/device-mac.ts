import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { Mac0, type Mac0Structure } from '../../cose/mac0'

export type DeviceMacStructure = Mac0Structure

export class DeviceMac extends Mac0 {
  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceMac {
    const data = cborDecode<DeviceMacStructure>(bytes, options)
    return DeviceMac.fromEncodedStructure(data)
  }

  public static override fromEncodedStructure(encodedStructure: DeviceMacStructure): DeviceMac {
    return new DeviceMac({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      tag: encodedStructure[3],
    })
  }
}
