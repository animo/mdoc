import { CborStructure, DataItem } from '../../cbor'
import { DeviceAuth, type DeviceAuthStructure } from './device-auth'
import { DeviceNamespaces, type DeviceNamespacesStructure } from './device-namespaces'

export type DeviceSignedStructure = {
  nameSpaces: DataItem<DeviceNamespacesStructure>
  deviceAuth: DeviceAuthStructure
}

export type DeviceSignedOptions = {
  deviceNamespaces: DeviceNamespaces
  deviceAuth: DeviceAuth
}

export class DeviceSigned extends CborStructure {
  public deviceNamespaces: DeviceNamespaces
  public deviceAuth: DeviceAuth

  public constructor(options: DeviceSignedOptions) {
    super()
    this.deviceNamespaces = options.deviceNamespaces
    this.deviceAuth = options.deviceAuth
  }

  public encodedStructure(): DeviceSignedStructure {
    return {
      nameSpaces: DataItem.fromData(this.deviceNamespaces.encodedStructure()),
      deviceAuth: this.deviceAuth.encodedStructure(),
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceSignedStructure | Map<string, unknown>
  ): DeviceSigned {
    let structure = encodedStructure as DeviceSignedStructure

    if (encodedStructure instanceof Map) {
      structure = {
        nameSpaces: encodedStructure.get('nameSpaces') as DeviceSignedStructure['nameSpaces'],
        deviceAuth: encodedStructure.get('deviceAuth') as DeviceSignedStructure['deviceAuth'],
      }
    }

    return new DeviceSigned({
      deviceAuth: DeviceAuth.fromEncodedStructure(structure.deviceAuth),
      deviceNamespaces: DeviceNamespaces.fromEncodedStructure(structure.nameSpaces.data),
    })
  }
}
