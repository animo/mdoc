import { CborStructure, type DataItem, cborDecode } from '../../cbor'
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
    const deviceEngagementStructure = cborDecode<DataItem<DeviceEngagementStructure>>(encodedStructure[0]).data
    const eReaderKeyStructure = cborDecode<DataItem<EReaderKeyStructure>>(encodedStructure[1]).data
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
}
