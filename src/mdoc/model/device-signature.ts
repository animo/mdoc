import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { Sign1, type Sign1Structure } from '../../cose/sign1'

export type DeviceSignatureStructure = Sign1Structure

export class DeviceSignature extends Sign1 {
  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    const data = cborDecode<DeviceSignatureStructure>(bytes, options)
    return DeviceSignature.fromEncodedStructure(data)
  }

  public static override fromEncodedStructure(encodedStructure: DeviceSignatureStructure): DeviceSignature {
    return new DeviceSignature({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }
}
