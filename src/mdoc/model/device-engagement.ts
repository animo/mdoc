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
  extra?: Record<number, unknown>
}

export class DeviceEngagement extends CborStructure {
  public version: string
  public security: Security
  public deviceRetrievalMethods?: Array<DeviceRetrievalMethod>
  public serverRetrievalMethods?: Array<ServerRetrievalMethod>
  public protocolInfo?: ProtocolInfo
  public extra?: Record<number, unknown>

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

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceEngagement {
    const map = cborDecode<Map<number, unknown>>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    const version = map.get(0) as string
    const securityStructure = map.get(1) as SecurityStructure
    const deviceRetrievalMethodsStructure = map.get(2) as Array<DeviceRetrievalMethodStructure> | undefined
    const serverRetrievalMethodsStructure = map.get(3) as Array<ServerRetrievalMethodStructure> | undefined
    const protocolInfoStructure = map.get(4) as ProtocolInfoStructure | undefined

    const deviceRetrievalMethods = deviceRetrievalMethodsStructure?.map(DeviceRetrievalMethod.fromEncodedStructure)
    const serverRetrievalMethods = serverRetrievalMethodsStructure?.map(ServerRetrievalMethod.fromEncodedStructure)

    const definedKeys = [0, 1, 2, 3, 4]
    const extras: Record<number, unknown> = {}
    map.forEach((v, k) => {
      if (definedKeys.includes(k)) return
      extras[k] = v
    })

    return new DeviceEngagement({
      version,
      security: Security.fromEncodedStructure(securityStructure),
      deviceRetrievalMethods,
      serverRetrievalMethods,
      protocolInfo: protocolInfoStructure ? ProtocolInfo.fromEncodedStructure(protocolInfoStructure) : undefined,
      extra: extras,
    })
  }
}
