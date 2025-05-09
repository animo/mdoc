import { type CborDecodeOptions, CborStructure, DataItem, cborDecode, cborEncode } from '../../cbor'
import type { MdocContext } from '../../context'
import { DeviceEngagement, type DeviceEngagementStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import { NfcHandover, type NfcHandoverStructure } from './nfc-handover'
import { QrHandover, type QrHandoverStructure } from './qr-handover'

export type SessionTranscriptStructure = [
  DataItem<DeviceEngagementStructure> | null,
  DataItem<EReaderKeyStructure> | null,
  QrHandoverStructure | NfcHandoverStructure,
]

export type SessionTranscriptOptions = {
  deviceEngagement?: DeviceEngagement | null
  eReaderKey?: EReaderKey | null
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
    this.deviceEngagement = options.deviceEngagement ?? null
    this.eReaderKey = options.eReaderKey ?? null
    this.handover = options.handover
  }

  public encodedStructure(): SessionTranscriptStructure {
    return [
      this.deviceEngagement ? DataItem.fromData(this.deviceEngagement.encodedStructure()) : null,
      this.eReaderKey ? DataItem.fromData(this.eReaderKey.encodedStructure()) : null,
      this.handover.encodedStructure(),
    ]
  }

  public static async calculateSessionTranscriptBytesForOid4VpDcApi(
    options: { clientId: string; origin: string; verifierGeneratedNonce: string },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    return cborEncode(
      DataItem.fromData([
        null,
        null,
        [
          'OpenID4VPDCAPIHandover',
          await ctx.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([options.origin, options.clientId, options.verifierGeneratedNonce]),
          }),
        ],
      ])
    )
  }

  public static async calculateSessionTranscriptBytesForOid4Vp(
    options: { clientId: string; responseUri: string; verifierGeneratedNonce: string; mdocGeneratedNonce: string },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    return cborEncode(
      DataItem.fromData([
        null,
        null,
        [
          await ctx.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([options.clientId, options.mdocGeneratedNonce]),
          }),
          await ctx.crypto.digest({
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
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const readerEngagementBytesHash = await ctx.crypto.digest({
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
    const deviceEngagementStructure = encodedStructure[0]?.data
    const eReaderKeyStructure = encodedStructure[1]?.data
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
    return SessionTranscript.fromEncodedStructure(structure)
  }
}
