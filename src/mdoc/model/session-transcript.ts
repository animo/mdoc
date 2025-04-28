import { type CborDecodeOptions, CborStructure, cborDecode, cborEncode } from '../../cbor'
import { DeviceEngagement, type DeviceEngagementStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import { NfcHandover, type NfcHandoverStructure } from './nfc-handover'
import { QrHandover, type QrHandoverStructure } from './qr-handover'

export type SessionTranscriptStructure = [Uint8Array, Uint8Array, QrHandoverStructure | NfcHandoverStructure]

export type SessionTranscriptOptions = {
  deviceEngagement: DeviceEngagement
  eReaderKey: EReaderKey
  handover: QrHandover | NfcHandover
}

export class SessionTranscript extends CborStructure {
  public deviceEngagement: DeviceEngagement
  public eReaderKey: EReaderKey
  public handover: QrHandover | NfcHandover

  public constructor(options: SessionTranscriptOptions) {
    super()
    this.deviceEngagement = options.deviceEngagement
    this.eReaderKey = options.eReaderKey
    this.handover = options.handover
  }

  public encodedStructure(): SessionTranscriptStructure {
    return [
      this.deviceEngagement.encode({ asDataItem: true }),
      this.eReaderKey.encode({ asDataItem: true }),
      this.handover.encodedStructure(),
    ]
  }

  public static override fromEncodedStructure(encodedStructure: SessionTranscriptStructure): SessionTranscript {
    const deviceEngagementStructure = cborDecode<DeviceEngagementStructure>(encodedStructure[0])
    const eReaderKeyStructure = cborDecode<EReaderKeyStructure>(encodedStructure[1])
    const handoverStructure = encodedStructure[2] as QrHandoverStructure | NfcHandoverStructure

    const handover =
      handoverStructure === null
        ? QrHandover.fromEncodedStructure(handoverStructure)
        : NfcHandover.fromEncodedStructure(handoverStructure)

    return new SessionTranscript({
      deviceEngagement: DeviceEngagement.fromEncodedStructure(deviceEngagementStructure),
      eReaderKey: EReaderKey.fromEncodedStructure(eReaderKeyStructure),
      handover,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): SessionTranscript {
    const structure = cborDecode<SessionTranscriptStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return SessionTranscript.fromEncodedStructure([cborEncode(structure[0]), cborEncode(structure[1]), structure[2]])
  }
}
