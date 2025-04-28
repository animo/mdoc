import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { DeviceKey, type DeviceKeyStructure } from './device-key'
import { KeyAuthorizations, type KeyAuthorizationsStructure } from './key-authorizations'
import { KeyInfo, type KeyInfoStructure } from './key-info'

export type DeviceKeyInfoStructure = {
  deviceKey: DeviceKeyStructure
  keyAuthorizations?: KeyAuthorizationsStructure
  keyInfo?: KeyInfoStructure
}

export type DeviceKeyInfoOptions = {
  deviceKey: DeviceKey
  keyAuthorizations?: KeyAuthorizations
  keyInfo?: KeyInfo
}

export class DeviceKeyInfo extends CborStructure {
  public deviceKey: DeviceKey
  public keyAuthorizations?: KeyAuthorizations
  public keyInfo?: KeyInfo

  public constructor(options: DeviceKeyInfoOptions) {
    super()
    this.deviceKey = options.deviceKey
    this.keyAuthorizations = options.keyAuthorizations
    this.keyInfo = options.keyInfo
  }

  public encodedStructure(): DeviceKeyInfoStructure {
    const structure: DeviceKeyInfoStructure = { deviceKey: this.deviceKey.encodedStructure() }

    if (this.keyInfo) {
      structure.keyInfo = this.keyInfo.encodedStructure()
    }

    if (this.keyAuthorizations) {
      structure.keyAuthorizations = this.keyAuthorizations.encodedStructure()
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceKeyInfoStructure | Map<string, unknown>
  ): DeviceKeyInfo {
    let structure = encodedStructure as DeviceKeyInfoStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DeviceKeyInfoStructure
    }

    return new DeviceKeyInfo({
      deviceKey: DeviceKey.fromEncodedStructure(structure.deviceKey),
      keyAuthorizations: structure.keyAuthorizations
        ? KeyAuthorizations.fromEncodedStructure(structure.keyAuthorizations)
        : undefined,
      keyInfo: structure.keyInfo ? KeyInfo.fromEncodedStructure(structure.keyInfo) : undefined,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceKeyInfo {
    const map = cborDecode<DeviceKeyInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return DeviceKeyInfo.fromEncodedStructure(map)
  }
}
