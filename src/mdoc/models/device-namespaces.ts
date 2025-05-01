import { CborStructure } from '../../cbor'
import { DeviceSignedItems, type DeviceSignedItemsStructure } from './device-signed-items'
import type { Namespace } from './namespace'

export type DeviceNamespacesStructure = Map<Namespace, DeviceSignedItemsStructure>

export type DeviceNamespacesOptions = {
  deviceNamespaces: Map<Namespace, DeviceSignedItems>
}

export class DeviceNamespaces extends CborStructure {
  public deviceNamespaces: Map<Namespace, DeviceSignedItems>

  public constructor(options: DeviceNamespacesOptions) {
    super()
    this.deviceNamespaces = options.deviceNamespaces
  }

  public encodedStructure(): DeviceNamespacesStructure {
    const map: DeviceNamespacesStructure = new Map()

    this.deviceNamespaces.forEach((v, k) => {
      map.set(k, v.encodedStructure())
    })

    return map
  }

  public static override fromEncodedStructure(encodedStructure: DeviceNamespacesStructure): DeviceNamespaces {
    const deviceNamespaces = new Map<Namespace, DeviceSignedItems>()
    encodedStructure.forEach((v, k) => {
      deviceNamespaces.set(k, DeviceSignedItems.fromEncodedStructure(v))
    })

    return new DeviceNamespaces({ deviceNamespaces })
  }
}
