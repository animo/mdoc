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
  /**
   * Raw CBOR bytes for DeviceEngagement (used for QR handover to preserve exact bytes)
   * When provided, these bytes are used directly instead of re-encoding deviceEngagement
   */
  rawDeviceEngagementBytes?: Uint8Array
  /**
   * Raw CBOR bytes for EReaderKey (used for QR handover to preserve exact bytes)
   * When provided, these bytes are used directly instead of re-encoding eReaderKey
   */
  rawEReaderKeyBytes?: Uint8Array
}

export class SessionTranscript extends CborStructure {
  public deviceEngagement?: DeviceEngagement
  public eReaderKey?: EReaderKey
  public handover: Handover

  /**
   * Raw CBOR bytes for DeviceEngagement (preserves exact bytes for QR handover)
   */
  private rawDeviceEngagementBytes?: Uint8Array

  /**
   * Raw CBOR bytes for EReaderKey (preserves exact bytes for QR handover)
   */
  private rawEReaderKeyBytes?: Uint8Array

  public constructor(options: SessionTranscriptOptions) {
    super()
    this.deviceEngagement = options.deviceEngagement
    this.eReaderKey = options.eReaderKey
    this.handover = options.handover
    this.rawDeviceEngagementBytes = options.rawDeviceEngagementBytes
    this.rawEReaderKeyBytes = options.rawEReaderKeyBytes
  }

  public encodedStructure(): SessionTranscriptStructure {
    const isProximityHandover = this.handover instanceof QrHandover || this.handover instanceof NfcHandover

    if (isProximityHandover) {
      // QR/NFC handovers require raw bytes for exact CBOR encoding (session key derivation)
      const deviceEngagementBytes = this.rawDeviceEngagementBytes ?? this.deviceEngagement?.rawBytes
      const eReaderKeyBytes = this.rawEReaderKeyBytes ?? this.eReaderKey?.rawBytes

      if (!deviceEngagementBytes) {
        throw new Error('QR/NFC handover requires rawDeviceEngagementBytes or deviceEngagement.rawBytes')
      }
      if (!eReaderKeyBytes) {
        throw new Error('QR/NFC handover requires rawEReaderKeyBytes or eReaderKey.rawBytes')
      }

      return [
        new DataItem<DeviceEngagementStructure>({ buffer: deviceEngagementBytes }),
        new DataItem<EReaderKeyStructure>({ buffer: eReaderKeyBytes }),
        this.handover.encodedStructure(),
      ]
    }

    // OID4VP handovers don't use deviceEngagement/eReaderKey
    return [null, null, this.handover.encodedStructure()]
  }

  /**
   * Create a SessionTranscript for QR handover (ISO 18013-5 proximity presentation).
   *
   * For QR handover, exact CBOR bytes matter for session key derivation.
   * - DeviceEngagement.rawBytes is auto-preserved when using DeviceEngagement.decode()
   * - EReaderKey is auto-encoded with integer keys (RFC 8152)
   *
   * @param options.deviceEngagement - DeviceEngagement (use DeviceEngagement.decode() to preserve rawBytes)
   * @param options.eReaderKey - The reader's ephemeral public key
   * @param options.rawDeviceEngagementBytes - Optional explicit raw bytes (overrides deviceEngagement.rawBytes)
   * @param options.rawEReaderKeyBytes - Optional explicit raw bytes for EReaderKey
   */
  public static forQrHandover(options: {
    deviceEngagement: DeviceEngagement
    eReaderKey: EReaderKey
    rawDeviceEngagementBytes?: Uint8Array
    rawEReaderKeyBytes?: Uint8Array
  }) {
    return new SessionTranscript({
      deviceEngagement: options.deviceEngagement,
      eReaderKey: options.eReaderKey,
      handover: new QrHandover(),
      rawDeviceEngagementBytes: options.rawDeviceEngagementBytes,
      rawEReaderKeyBytes: options.rawEReaderKeyBytes,
    })
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
