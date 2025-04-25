import { CborStructure } from '../../cbor'

export type BleOptionsStructure = {
  0: boolean
  1: boolean
  10?: Uint8Array
  11?: Uint8Array
  20?: Uint8Array
}

export type BleOptionsOptions = {
  peripheralServerMode: boolean
  centralClientMode: boolean
  peripheralServerModeUuid?: Uint8Array
  centralClientModeUuid?: Uint8Array
  peripheralServerModeDeviceAddress?: Uint8Array
}

export class BleOptions extends CborStructure {
  public peripheralServerMode: boolean
  public centralClientMode: boolean
  public peripheralServerModeUuid?: Uint8Array
  public centralClientModeUuid?: Uint8Array
  public peripheralServerModeDeviceAddress?: Uint8Array

  public constructor(options: BleOptionsOptions) {
    super()
    this.peripheralServerMode = options.peripheralServerMode
    this.centralClientMode = options.centralClientMode
    this.peripheralServerModeUuid = options.peripheralServerModeUuid
    this.centralClientModeUuid = options.centralClientModeUuid
    this.peripheralServerModeDeviceAddress = options.peripheralServerModeDeviceAddress
  }

  public encodedStructure(): BleOptionsStructure {
    const structure: BleOptionsStructure = {
      0: this.peripheralServerMode,
      1: this.centralClientMode,
    }

    if (this.peripheralServerModeUuid) {
      structure[10] = this.peripheralServerModeUuid
    }

    if (this.centralClientModeUuid) {
      structure[11] = this.centralClientModeUuid
    }

    if (this.peripheralServerModeDeviceAddress) {
      structure[20] = this.peripheralServerModeDeviceAddress
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: BleOptionsStructure | Map<number, unknown>
  ): CborStructure {
    let structure = encodedStructure as BleOptionsStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as BleOptionsStructure
    }

    return new BleOptions({
      peripheralServerMode: structure[0],
      centralClientMode: structure[1],
      peripheralServerModeUuid: structure[10],
      centralClientModeUuid: structure[11],
      peripheralServerModeDeviceAddress: structure[20],
    })
  }
}
