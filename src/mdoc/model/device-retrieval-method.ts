import { CborStructure } from '../../cbor'
import { CborEncodeError } from '../../cbor/error'
import { BleOptions } from './ble-options'
import { NfcOptions } from './nfc-options'
import type { RetrievalOptions, RetrievalOptionsStructure } from './retrieval-options'
import { WifiOptions } from './wifi-options'

export enum DeviceRetrievalMethodType {
  Nfc = 1,
  Ble = 2,
  WifiAware = 3,
}

export type DeviceRetrievalMethodStructure = [DeviceRetrievalMethodType, number, RetrievalOptionsStructure]

export type DeviceRetrievalMethodOptions = {
  type: DeviceRetrievalMethodType | number
  version: number
  retrievalOptions: RetrievalOptions
}

export class DeviceRetrievalMethod extends CborStructure {
  public type: DeviceRetrievalMethodType
  public version: number
  public retrievalOptions: RetrievalOptions

  public constructor(options: DeviceRetrievalMethodOptions) {
    super()
    this.type = options.type
    this.version = options.version
    this.retrievalOptions = options.retrievalOptions
  }

  public encodedStructure(): DeviceRetrievalMethodStructure {
    return [this.type, this.version, this.retrievalOptions.encodedStructure()]
  }

  public static override fromEncodedStructure(encodedStructure: DeviceRetrievalMethodStructure): DeviceRetrievalMethod {
    const type = encodedStructure[0]
    const version = encodedStructure[1]
    const retrievalOptions = encodedStructure[2]

    const RetrievalOptionsCls =
      type === DeviceRetrievalMethodType.Nfc
        ? NfcOptions
        : type === DeviceRetrievalMethodType.Ble
          ? BleOptions
          : type === DeviceRetrievalMethodType.WifiAware
            ? WifiOptions
            : undefined

    if (!RetrievalOptionsCls) {
      throw new CborEncodeError(`Type '${type}' does not match a valid device retrieval type`)
    }

    return new DeviceRetrievalMethod({
      type,
      version,
      retrievalOptions: RetrievalOptionsCls.fromEncodedStructure(
        retrievalOptions as Map<number, unknown>
      ) as RetrievalOptions,
    })
  }
}
