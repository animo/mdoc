import { type CborDecodeOptions, CborStructure, cborDecode, cborEncode } from '../../cbor'
import type { DeviceKeyInfo, DigestAlgorithm, ValidityInfo } from './types'

export type MsoOptions = {
  digestAlgorithm: DigestAlgorithm
  docType: string
  version: string
  validityInfo: ValidityInfo
  valueDigests?: Map<string, Map<number, Uint8Array>>
  validityDigests?: Record<string, Map<number, Uint8Array>>
  deviceKeyInfo?: DeviceKeyInfo
}

export class Mso extends CborStructure {
  public version: string
  public digestAlgorithm: DigestAlgorithm
  public docType: string
  public validityInfo: ValidityInfo
  public valueDigests?: Map<string, Map<number, Uint8Array>>
  public validityDigests?: Record<string, Map<number, Uint8Array>>
  public deviceKeyInfo?: DeviceKeyInfo

  public constructor(options: MsoOptions) {
    super()
    this.version = options.version
    this.digestAlgorithm = options.digestAlgorithm
    this.docType = options.docType
    this.validityInfo = options.validityInfo
    this.valueDigests = options.valueDigests
    this.validityDigests = options.validityDigests
    this.deviceKeyInfo = options.deviceKeyInfo
  }

  public encodedStructure(): unknown {
    return cborEncode({
      version: this.version,
      digestAlgorithm: this.digestAlgorithm,
      valueDigests: this.valueDigests,
      deviceKeyInfo: this.deviceKeyInfo,
      docType: this.docType,
      validityInfo: this.validityInfo,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Mso {
    const msoOptions = cborDecode<MsoOptions>(bytes, options)

    // @todo this should happen in the `Mso.decode` method
    // const mapValidityInfo = (validityInfo?: Map<string, Uint8Array>) => {
    //   if (!validityInfo) {
    //     return validityInfo
    //   }
    //   return Object.fromEntries(
    //     [...validityInfo.entries()].map(([key, value]) => {
    //       return [key, value instanceof Uint8Array ? cborDecode(value) : value]
    //     })
    //   )
    // }

    // const result: MSO = {
    //   ...decodedEntries,
    //   validityInfo: mapValidityInfo(decodedEntries.validityInfo),
    //   validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : undefined,
    //   deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : undefined,
    // }
    // this.#decodedPayload = result
    // return result

    return new Mso(msoOptions)
  }
}
