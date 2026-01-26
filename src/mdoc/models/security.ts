import { type CborDecodeOptions, CborStructure, cborDecode, DataItem } from '../../cbor'
import type { EncodedCoseKeyStructure } from '../../cose'
import { EDeviceKey } from './e-device-key'

export type SecurityStructure = [number, DataItem<EncodedCoseKeyStructure>]

export type SecurityOptions = {
  cipherSuiteIdentifier: number
  eDeviceKey: EDeviceKey
}

export class Security extends CborStructure {
  // TODO: enum
  public cipherSuiteIdentifier: number
  public eDeviceKey: EDeviceKey

  public constructor(options: SecurityOptions) {
    super()
    this.cipherSuiteIdentifier = options.cipherSuiteIdentifier
    this.eDeviceKey = options.eDeviceKey
  }

  public encodedStructure(): SecurityStructure {
    return [this.cipherSuiteIdentifier, DataItem.fromData(this.eDeviceKey.encodedStructure())]
  }

  public static override fromEncodedStructure(encodedStructure: SecurityStructure): Security {
    const eDeviceKeyStructure = encodedStructure[1].data

    return new Security({
      cipherSuiteIdentifier: encodedStructure[0],
      eDeviceKey: EDeviceKey.fromEncodedStructure(eDeviceKeyStructure),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Security {
    const structure = cborDecode<SecurityStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Security.fromEncodedStructure(structure)
  }
}
