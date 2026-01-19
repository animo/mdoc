import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { DeviceRetrievalMethod, type DeviceRetrievalMethodStructure } from './device-retrieval-method'
import { ProtocolInfo, type ProtocolInfoStructure } from './protocol-info'
import { Security, type SecurityStructure } from './security'
import { ServerRetrievalMethod, type ServerRetrievalMethodStructure } from './server-retrieval-method'

export type DeviceEngagementStructure = {
  0: string
  1: SecurityStructure
  2?: Array<DeviceRetrievalMethodStructure>
  3?: Array<ServerRetrievalMethodStructure>
  4?: ProtocolInfoStructure
} & Record<number, unknown>

export type DeviceEngagementOptions = {
  version: string
  security: Security
  deviceRetrievalMethods?: Array<DeviceRetrievalMethod>
  serverRetrievalMethods?: Array<ServerRetrievalMethod>
  protocolInfo?: ProtocolInfo
  extra?: Record<string, unknown>
}

export class DeviceEngagement extends CborStructure {
  public version: string
  public security: Security
  public deviceRetrievalMethods?: Array<DeviceRetrievalMethod>
  public serverRetrievalMethods?: Array<ServerRetrievalMethod>
  public protocolInfo?: ProtocolInfo
  public extra?: Record<string, unknown>

  /**
   * Original CBOR bytes (preserved when decoding for QR handover session transcript)
   */
  public rawBytes?: Uint8Array

  public constructor(options: DeviceEngagementOptions) {
    super()
    this.version = options.version
    this.security = options.security
    this.deviceRetrievalMethods = options.deviceRetrievalMethods
    this.serverRetrievalMethods = options.serverRetrievalMethods
    this.protocolInfo = options.protocolInfo
    this.extra = options.extra
  }

  public encodedStructure(): DeviceEngagementStructure {
    let structure: DeviceEngagementStructure = {
      0: this.version,
      1: this.security.encodedStructure(),
    }

    if (this.deviceRetrievalMethods) {
      structure[2] = this.deviceRetrievalMethods.map((drm) => drm.encodedStructure())
    }

    if (this.serverRetrievalMethods) {
      structure[3] = this.serverRetrievalMethods.map((srm) => srm.encodedStructure())
    }

    if (this.protocolInfo) {
      structure[4] = this.protocolInfo.encodedStructure()
    }

    if (this.extra) {
      structure = { ...structure, ...this.extra }
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceEngagementStructure | Map<unknown, unknown>
  ): DeviceEngagement {
    let structure = encodedStructure as DeviceEngagementStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DeviceEngagementStructure
    }

    const definedKeys = ['0', '1', '2', '3', '4']
    const extras: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(structure)) {
      if (definedKeys.includes(k)) continue
      extras[k] = v
    }

    return new DeviceEngagement({
      version: structure[0],
      security: Security.fromEncodedStructure(structure[1]),
      deviceRetrievalMethods: structure[2] ? structure[2].map(DeviceRetrievalMethod.fromEncodedStructure) : undefined,
      serverRetrievalMethods: structure[3] ? structure[3].map(ServerRetrievalMethod.fromEncodedStructure) : undefined,
      protocolInfo: structure[4] ? ProtocolInfo.fromEncodedStructure(structure[4]) : undefined,
      extra: extras,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceEngagement {
    const structure = cborDecode<DeviceEngagementStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    const engagement = DeviceEngagement.fromEncodedStructure(structure)
    // Preserve original bytes for QR handover session transcript
    engagement.rawBytes = bytes
    return engagement
  }
}
