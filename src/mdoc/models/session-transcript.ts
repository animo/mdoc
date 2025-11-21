import { type CborDecodeOptions, CborStructure, cborDecode, DataItem } from '../../cbor'
import type { MdocContext } from '../../context'
import { DeviceEngagement, type DeviceEngagementStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import type { Handover } from './handover'
import { NfcHandover } from './nfc-handover'
import {
  Oid4vpDcApiDraft24HandoverInfo,
  type Oid4vpDcApiDraft24HandoverInfoOptions,
} from './oid4vp-dc-api-draft24-handover-info'
import { Oid4vpDcApiHandover } from './oid4vp-dc-api-handover'
import { Oid4vpDcApiHandoverInfo, type Oid4vpDcApiHandoverInfoOptions } from './oid4vp-dc-api-handover-info'
import { Oid4vpDraft18Handover } from './oid4vp-draft18-handover'
import { Oid4vpHandover } from './oid4vp-handover'
import { Oid4vpHandoverInfo, type Oid4vpHandoverInfoOptions } from './oid4vp-handover-info'
import { QrHandover } from './qr-handover'

export type SessionTranscriptStructure = [
  DataItem<DeviceEngagementStructure> | null,
  DataItem<EReaderKeyStructure> | null,
  unknown,
]

export type SessionTranscriptOptions = {
  deviceEngagement?: DeviceEngagement
  eReaderKey?: EReaderKey
  handover: CborStructure
}

export class SessionTranscript extends CborStructure {
  public deviceEngagement?: DeviceEngagement
  public eReaderKey?: EReaderKey
  public handover: Handover

  public constructor(options: SessionTranscriptOptions) {
    super()
    this.deviceEngagement = options.deviceEngagement
    this.eReaderKey = options.eReaderKey
    this.handover = options.handover
  }

  public encodedStructure(): SessionTranscriptStructure {
    return [
      this.deviceEngagement ? DataItem.fromData(this.deviceEngagement.encodedStructure()) : null,
      this.eReaderKey ? DataItem.fromData(this.eReaderKey.encodedStructure()) : null,
      this.handover.encodedStructure(),
    ]
  }

  public static async forOid4VpDcApiDraft24(
    options: Oid4vpDcApiDraft24HandoverInfoOptions,
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const info = new Oid4vpDcApiDraft24HandoverInfo(options)
    const handover = new Oid4vpDcApiHandover({ oid4vpDcApiHandoverInfo: info })
    await handover.prepare(ctx)

    return new SessionTranscript({ handover })
  }

  public static async forOid4VpDcApi(options: Oid4vpDcApiHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = new Oid4vpDcApiHandoverInfo(options)
    const handover = new Oid4vpDcApiHandover({ oid4vpDcApiHandoverInfo: info })
    await handover.prepare(ctx)

    return new SessionTranscript({ handover })
  }

  public static async forOid4Vp(options: Oid4vpHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = new Oid4vpHandoverInfo(options)
    const handover = new Oid4vpHandover({ oid4vpHandoverInfo: info })
    await handover.prepare(ctx)

    return new SessionTranscript({ handover })
  }

  /**
   * Calculate the session transcript bytes as defined in 18013-7 first edition, based
   * on OpenID4VP draft 18.
   */
  public static async forOid4VpDraft18(
    options: { clientId: string; responseUri: string; verifierGeneratedNonce: string; mdocGeneratedNonce: string },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const handover = new Oid4vpDraft18Handover({
      clientId: options.clientId,
      nonce: options.verifierGeneratedNonce,
      mdocGeneratedNonce: options.mdocGeneratedNonce,
      responseUri: options.responseUri,
    })
    await handover.prepare(ctx)

    return new SessionTranscript({ handover })
  }

  public static override fromEncodedStructure(encodedStructure: SessionTranscriptStructure): SessionTranscript {
    const deviceEngagementStructure = encodedStructure[0]?.data
    const eReaderKeyStructure = encodedStructure[1]?.data
    const handoverStructure = encodedStructure[2]

    const isNfcHandover = NfcHandover.isCorrectHandover(handoverStructure)
    const isQrHandover = QrHandover.isCorrectHandover(handoverStructure)
    const isOid4vpHandover = Oid4vpHandover.isCorrectHandover(handoverStructure)
    const isOid4vpDraft18Handover = Oid4vpDraft18Handover.isCorrectHandover(handoverStructure)
    const isOid4vpDcApiHandover = Oid4vpDcApiHandover.isCorrectHandover(handoverStructure)

    const handover = isNfcHandover
      ? NfcHandover.fromEncodedStructure(handoverStructure)
      : isQrHandover
        ? QrHandover.fromEncodedStructure(handoverStructure)
        : isOid4vpHandover
          ? Oid4vpHandover.fromEncodedStructure(handoverStructure)
          : isOid4vpDraft18Handover
            ? Oid4vpDraft18Handover.fromEncodedStructure(handoverStructure)
            : isOid4vpDcApiHandover
              ? Oid4vpDcApiHandover.fromEncodedStructure(handoverStructure)
              : undefined

    if (!handover) {
      throw new Error('Could not establish specific handover structure')
    }

    return new SessionTranscript({
      deviceEngagement: deviceEngagementStructure
        ? DeviceEngagement.fromEncodedStructure(deviceEngagementStructure)
        : undefined,
      eReaderKey: eReaderKeyStructure ? EReaderKey.fromEncodedStructure(eReaderKeyStructure) : undefined,
      handover,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): SessionTranscript {
    const structure = cborDecode<SessionTranscriptStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return SessionTranscript.fromEncodedStructure(structure)
  }
}
