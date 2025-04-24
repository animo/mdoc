import { CborStructure } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'

export type DeviceSignedItemsStructure = Map<DataElementIdentifier, DataElementValue>

export type DeviceSignedOptions = {
  deviceSignedItems: Map<DataElementIdentifier, DataElementValue>
}

export class DeviceSignedItems extends CborStructure {
  deviceSignedItems: Map<DataElementIdentifier, DataElementValue>

  public constructor(options: DeviceSignedOptions) {
    super()
    this.deviceSignedItems = options.deviceSignedItems
  }

  public encodedStructure(): DeviceSignedItemsStructure {
    return this.deviceSignedItems
  }

  public static override fromEncodedStructure(encodedStructure: DeviceSignedItemsStructure): DeviceSignedItems {
    return new DeviceSignedItems({ deviceSignedItems: encodedStructure })
  }
}
