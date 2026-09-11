import { base64url } from '@owf/identity-common'
import type { MdocContext } from './context'
import {
  DeviceRequest,
  DeviceResponse,
  type DeviceResponseDocumentOptions,
  IssuerSigned,
  type IssuerSignedVerificationResult,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'
import { type HolderDeviceRequestMatchResult, matchCredentialsToDeviceRequest } from './utils/matchDeviceRequest'

export class Holder {
  /**
   *
   * string should be base64url encoded as defined in openid4vci
   *
   */
  public static async verifyIssuerSigned(
    options: {
      issuerSigned: Uint8Array | string | IssuerSigned
      verificationCallback?: VerificationCallback
      now?: Date
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates?: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ): Promise<IssuerSignedVerificationResult> {
    const issuerSigned =
      typeof options.issuerSigned === 'string'
        ? IssuerSigned.decode(base64url.decode(options.issuerSigned))
        : options.issuerSigned instanceof Uint8Array
          ? IssuerSigned.decode(options.issuerSigned)
          : options.issuerSigned

    return await issuerSigned.verify(options, ctx)
  }

  public static async verifyDeviceRequest(
    options: {
      deviceRequest: Uint8Array | DeviceRequest
      sessionTranscript: Uint8Array | SessionTranscript
      verificationCallback?: VerificationCallback
      /**
       * Trust anchors for the reader's certificate chain. When provided, each
       * `DocRequest.readerAuth` chain is validated against these anchors (e.g.
       * CAs listed in a RICAL — Reader Identification CA List, defined in
       * ISO/IEC 18013-5 second edition Annex F).
       *
       * When omitted, reader-auth signatures are verified but chain trust is
       * not established — equivalent to first-edition behaviour.
       */
      trustedCertificates?: Array<Uint8Array>
      /**
       * Reference time for certificate `notBefore`/`notAfter` checks during
       * chain validation. Defaults to the current time.
       */
      now?: Date
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const deviceRequest =
      options.deviceRequest instanceof DeviceRequest
        ? options.deviceRequest
        : DeviceRequest.decode(options.deviceRequest)

    const sessionTranscript =
      options.sessionTranscript instanceof SessionTranscript
        ? options.sessionTranscript
        : SessionTranscript.decode(options.sessionTranscript)

    for (const docRequest of deviceRequest.docRequests) {
      await docRequest.readerAuth?.verify(
        {
          readerAuthentication: {
            itemsRequest: docRequest.itemsRequest,
            sessionTranscript,
          },
          verificationCallback: options.verificationCallback,
          trustedCertificates: options.trustedCertificates,
          now: options.now,
        },
        ctx
      )
    }
  }

  /**
   * Match the credentials of the holder against a device request, to select which credentials can
   * answer which doc request.
   *
   * Reports per doc request, per credential and per check (docType and claims) whether the
   * credential satisfies the doc request, so a holder can show which credentials match, and for a
   * credential of the right docType which requested elements it is missing. Credentials are referred
   * to by their index in `credentials`.
   *
   * A requested element is disclosed issuer-signed when the issuer signed it (or, for an
   * `age_over_NN` request, the age attestation 18013-5 7.2.5 allows in its place). Otherwise it is
   * disclosed device-signed when the device key is authorized for it in the MSO, and its value has
   * to be provided in the device namespaces when creating the response.
   *
   * Applies the same rules as `Verifier.matchDeviceRequest`.
   */
  public static matchDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    credentials: Array<IssuerSigned>
  }): HolderDeviceRequestMatchResult {
    return matchCredentialsToDeviceRequest({
      deviceRequest:
        options.deviceRequest instanceof DeviceRequest
          ? options.deviceRequest
          : DeviceRequest.decode(options.deviceRequest),
      credentials: options.credentials,
    })
  }

  public static async createDeviceResponseForDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      documents: Array<DeviceResponseDocumentOptions>
    },
    context: Pick<MdocContext, 'cose' | 'crypto'>
  ) {
    return await DeviceResponse.createWithDeviceRequest(options, context)
  }
}
