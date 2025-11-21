import { type CborDecodeOptions, CborStructure, cborDecode, DataItem } from '../../cbor'
import { DeviceNamespaces, type DeviceNamespacesStructure } from './device-namespaces'
import type { DocType } from './doctype'
import { SessionTranscript, type SessionTranscriptStructure } from './session-transcript'

export type DeviceAuthenticationStructure = [
  string,
  SessionTranscriptStructure,
  DocType,
  DataItem<DeviceNamespacesStructure>,
]

export type DeviceAuthenticationOptions = {
  sessionTranscript: SessionTranscript | Uint8Array
  docType: DocType
  deviceNamespaces: DeviceNamespaces
}

export class DeviceAuthentication extends CborStructure {
  public sessionTranscript: SessionTranscript | Uint8Array
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
      this.sessionTranscript instanceof SessionTranscript
        ? this.sessionTranscript.encodedStructure()
        : cborDecode(this.sessionTranscript),
      this.docType,
      DataItem.fromData(this.deviceNamespaces.encodedStructure()),
    ]
  }

  public static override fromEncodedStructure(encodedStructure: DeviceAuthenticationStructure): DeviceAuthentication {
    return new DeviceAuthentication({
      sessionTranscript: SessionTranscript.fromEncodedStructure(encodedStructure[1]),
      docType: encodedStructure[2],
      deviceNamespaces: DeviceNamespaces.fromEncodedStructure(encodedStructure[3].data),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceAuthentication {
    const structure = cborDecode<DeviceAuthenticationStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return DeviceAuthentication.fromEncodedStructure(structure)
  }
}
