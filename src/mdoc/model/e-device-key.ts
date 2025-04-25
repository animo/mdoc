import { CborStructure } from '../../cbor'

export type EDeviceKeyStructure = never

export type EDeviceKeyOptions = never

export class EDeviceKey extends CborStructure {
  public encodedStructure(): EDeviceKeyStructure {
    throw new Error('Method not implemented.')
  }

  public static override fromEncodedStructure(encodedStructure: EDeviceKeyStructure): EDeviceKey {
    return new EDeviceKey()
  }
}
