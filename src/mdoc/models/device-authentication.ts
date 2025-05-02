import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { DeviceNamespaces } from './device-namespaces'
import type { DocType } from './doctype'
import { SessionTranscript } from './session-transcript'

export type DeviceAuthenticationStructure = [string, Uint8Array, DocType, Uint8Array]

export type DeviceAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  docType: DocType
  deviceNamespaces: DeviceNamespaces
}

export class DeviceAuthentication extends CborStructure {
  public sessionTranscript: SessionTranscript
  public docType: DocType
  public deviceNamespaces: DeviceNamespaces

  public constructor(options: DeviceAuthenticationOptions) {
    super()
    this.sessionTranscript = options.sessionTranscript
    this.docType = options.docType
    this.deviceNamespaces = options.deviceNamespaces
  }

  public encodedStructure(): DeviceAuthenticationStructure {
    return [
      'DeviceAuthentication',
      this.sessionTranscript.encode({ asDataItem: true }),
      this.docType,
      this.deviceNamespaces.encode({ asDataItem: true }),
    ]
  }

  public static override fromEncodedStructure(encodedStructure: DeviceAuthenticationStructure): DeviceAuthentication {
    return new DeviceAuthentication({
      sessionTranscript: SessionTranscript.decode(encodedStructure[1]),
      docType: encodedStructure[2],
      deviceNamespaces: DeviceNamespaces.decode(encodedStructure[3]),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceAuthentication {
    const structure = cborDecode<DeviceAuthenticationStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return DeviceAuthentication.fromEncodedStructure(structure)
  }
}
