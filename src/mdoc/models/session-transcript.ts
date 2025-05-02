import { type CborDecodeOptions, CborStructure, DataItem, cborDecode, cborEncode } from '../../cbor'
import type { MdocContext } from '../../context'
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

/**
 *
 * @todo Structure of the SessionTranscript class is very much based on the proximity flow.
 *       It should be extensible to work with all the different API's
 *
 */
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

  public static async calculateSessionTranscriptBytesForOid4VpDcApi(
    options: { clientId: string; origin: string; verifierGeneratedNonce: string },
    context: { crypto: MdocContext['crypto'] }
  ) {
    return cborEncode(
      DataItem.fromData([
        null,
        null,
        [
          'OpenID4VPDCAPIHandover',
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([options.origin, options.clientId, options.verifierGeneratedNonce]),
          }),
        ],
      ])
    )
  }

  public static async calculateSessionTranscriptBytesForOid4Vp(
    options: { clientId: string; responseUri: string; verifierGeneratedNonce: string; mdocGeneratedNonce: string },
    context: { crypto: MdocContext['crypto'] }
  ) {
    return cborEncode(
      DataItem.fromData([
        null,
        null,
        [
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([options.clientId, options.mdocGeneratedNonce]),
          }),
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([options.responseUri, options.mdocGeneratedNonce]),
          }),
          options.verifierGeneratedNonce,
        ],
      ])
    )
  }

  public static async calculateSessionTranscriptBytesForWebApi(
    options: {
      deviceEngagement: DeviceEngagement
      eReaderKey: EReaderKey
      readerEngagementBytes: Uint8Array
    },
    context: { crypto: MdocContext['crypto'] }
  ) {
    const readerEngagementBytesHash = await context.crypto.digest({
      bytes: options.readerEngagementBytes,
      digestAlgorithm: 'SHA-256',
    })

    return cborEncode(
      DataItem.fromData([
        new DataItem({ buffer: options.deviceEngagement.encode() }),
        new DataItem({ buffer: options.eReaderKey.encode() }),
        readerEngagementBytesHash,
      ])
    )
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
