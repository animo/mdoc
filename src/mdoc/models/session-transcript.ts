import { type CborDecodeOptions, CborStructure, cborDecode, cborEncode } from '../../cbor'
import { DeviceEngagement, type DeviceEngagementStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import { NfcHandover, type NfcHandoverStructure } from './nfc-handover'
import { QrHandover, type QrHandoverStructure } from './qr-handover'

export type SessionTranscriptStructure = [
  Uint8Array | null,
  Uint8Array | null,
  QrHandoverStructure | NfcHandoverStructure,
]

export type SessionTranscriptOptions = {
  deviceEngagement: DeviceEngagement | null
  eReaderKey: EReaderKey | null
  handover: QrHandover | NfcHandover
}

export class SessionTranscript extends CborStructure {
  public deviceEngagement: DeviceEngagement | null
  public eReaderKey: EReaderKey | null
  public handover: QrHandover | NfcHandover

  public constructor(options: SessionTranscriptOptions) {
    super()
    this.deviceEngagement = options.deviceEngagement
    this.eReaderKey = options.eReaderKey
    this.handover = options.handover
  }

  public encodedStructure(): SessionTranscriptStructure {
    return [
      this.deviceEngagement ? this.deviceEngagement.encode({ asDataItem: true }) : null,
      this.eReaderKey ? this.eReaderKey.encode({ asDataItem: true }) : null,
      this.handover.encodedStructure(),
    ]
  }

  public static override fromEncodedStructure(encodedStructure: SessionTranscriptStructure): SessionTranscript {
    const deviceEngagementStructure = encodedStructure[0]
      ? cborDecode<DeviceEngagementStructure>(encodedStructure[0])
      : null
    const eReaderKeyStructure = encodedStructure[1] ? cborDecode<EReaderKeyStructure>(encodedStructure[1]) : null
    const handoverStructure = encodedStructure[2] as QrHandoverStructure | NfcHandoverStructure

    const handover =
      handoverStructure === null
        ? QrHandover.fromEncodedStructure(handoverStructure)
        : NfcHandover.fromEncodedStructure(handoverStructure)

    return new SessionTranscript({
      deviceEngagement: deviceEngagementStructure
        ? DeviceEngagement.fromEncodedStructure(deviceEngagementStructure)
        : null,
      eReaderKey: eReaderKeyStructure ? EReaderKey.fromEncodedStructure(eReaderKeyStructure) : null,
      handover,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): SessionTranscript {
    const structure = cborDecode<SessionTranscriptStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return SessionTranscript.fromEncodedStructure([cborEncode(structure[0]), cborEncode(structure[1]), structure[2]])
  }
}
