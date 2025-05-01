import { CborStructure } from '../../cbor'

export type WifiOptionsStructure = {
  0?: string
  1?: number
  2?: number
  3?: Uint8Array
}

export type WifiOptionsOptions = {
  passPhrase?: string
  channelInfoOperatingClass?: number
  channelInfoChannelNumber?: number
  bandInfoSupportedBands?: Uint8Array
}

export class WifiOptions extends CborStructure {
  public passPhrase?: string
  public channelInfoOperatingClass?: number
  public channelInfoChannelNumber?: number
  public bandInfoSupportedBands?: Uint8Array

  public constructor(options: WifiOptionsOptions) {
    super()
    this.passPhrase = options.passPhrase
    this.channelInfoOperatingClass = options.channelInfoOperatingClass
    this.channelInfoChannelNumber = options.channelInfoChannelNumber
    this.bandInfoSupportedBands = options.bandInfoSupportedBands
  }

  public encodedStructure(): WifiOptionsStructure {
    const structure: WifiOptionsStructure = {}

    if (this.passPhrase) {
      structure[0] = this.passPhrase
    }

    if (this.channelInfoChannelNumber) {
      structure[1] = this.channelInfoChannelNumber
    }

    if (this.channelInfoOperatingClass) {
      structure[2] = this.channelInfoOperatingClass
    }

    if (this.bandInfoSupportedBands) {
      structure[3] = this.bandInfoSupportedBands
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: WifiOptionsStructure | Map<number, unknown>
  ): WifiOptions {
    let structure = encodedStructure as WifiOptionsStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as WifiOptionsStructure
    }

    return new WifiOptions({
      passPhrase: structure[0],
      channelInfoChannelNumber: structure[1],
      channelInfoOperatingClass: structure[2],
      bandInfoSupportedBands: structure[3],
    })
  }
}
