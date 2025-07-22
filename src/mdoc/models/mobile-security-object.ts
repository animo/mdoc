import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { DigestAlgorithm } from '../../cose'
import { DeviceKeyInfo, type DeviceKeyInfoStructure } from './device-key-info'
import type { DocType } from './doctype'
import { StatusInfo, type StatusInfoStructure } from './status-info'
import { ValidityInfo, type ValidityInfoStructure } from './validity-info'
import { ValueDigests, type ValueDigestsStructure } from './value-digests'

export type MobileSecurityObjectStructure = {
  version: string
  digestAlgorithm: string
  docType: string
  valueDigests: ValueDigestsStructure
  deviceKeyInfo: DeviceKeyInfoStructure
  validityInfo: ValidityInfoStructure
  status?: StatusInfoStructure
}

export type MobileSecurityObjectOptions = {
  version?: string
  digestAlgorithm: DigestAlgorithm
  docType: DocType
  valueDigests: ValueDigests
  validityInfo: ValidityInfo
  deviceKeyInfo: DeviceKeyInfo
  status?: StatusInfo
}

export class MobileSecurityObject extends CborStructure {
  public version: string
  public digestAlgorithm: DigestAlgorithm
  public docType: string
  public validityInfo: ValidityInfo
  public valueDigests: ValueDigests
  public deviceKeyInfo: DeviceKeyInfo
  public status?: StatusInfo

  public constructor(options: MobileSecurityObjectOptions) {
    super()
    this.version = options.version ?? '1.0'
    this.digestAlgorithm = options.digestAlgorithm
    this.docType = options.docType
    this.validityInfo = options.validityInfo
    this.valueDigests = options.valueDigests
    this.deviceKeyInfo = options.deviceKeyInfo
    this.status = options.status
  }

  public encodedStructure(): MobileSecurityObjectStructure {
    const structure: MobileSecurityObjectStructure = {
      version: this.version,
      digestAlgorithm: this.digestAlgorithm,
      valueDigests: this.valueDigests.encodedStructure(),
      deviceKeyInfo: this.deviceKeyInfo.encodedStructure(),
      docType: this.docType,
      validityInfo: this.validityInfo.encodedStructure(),
    }
    if (this.status) {
      structure.status = this.status.encodedStructure()
    }
    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: MobileSecurityObjectStructure | Map<string, unknown>
  ): MobileSecurityObject {
    let structure = encodedStructure as MobileSecurityObjectStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as MobileSecurityObjectStructure
    }

    const mobileSecurityObject: MobileSecurityObjectOptions = {
      version: structure.version,
      digestAlgorithm: structure.digestAlgorithm as DigestAlgorithm,
      docType: structure.docType,
      validityInfo: ValidityInfo.fromEncodedStructure(structure.validityInfo),
      valueDigests: ValueDigests.fromEncodedStructure(structure.valueDigests),
      deviceKeyInfo: DeviceKeyInfo.fromEncodedStructure(structure.deviceKeyInfo),
    }
    if (structure.status) {
      mobileSecurityObject.status = StatusInfo.fromEncodedStructure(structure.status)
    }
    return new MobileSecurityObject(mobileSecurityObject)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): MobileSecurityObject {
    const structure = cborDecode<MobileSecurityObjectStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    return MobileSecurityObject.fromEncodedStructure(structure)
  }
}
