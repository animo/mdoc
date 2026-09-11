import type { CoseKey } from '@owf/cose'
import type { MdocContext } from './context.js'
import type { VerificationCallback } from './mdoc/check-callback.js'
import {
  DeviceRequest,
  DeviceResponse,
  type DeviceResponseVerificationResult,
  type SessionTranscript,
} from './mdoc/index.js'
import {
  type DeviceRequestMatchOptions,
  type DeviceRequestMatchResult,
  matchDeviceRequest,
} from './utils/matchDeviceRequest.js'

export class Verifier {
  public static async verifyDeviceResponse(
    options: {
      deviceRequest?: DeviceRequest
      /**
       * Options to match the response against `deviceRequest` with: per doc request the elements
       * that are optional or that may be answered from `deviceSigned`. By default every requested
       * element is required and must be issuer-signed.
       */
      deviceRequestMatchOptions?: DeviceRequestMatchOptions
      deviceResponse: Uint8Array | DeviceResponse
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ): Promise<DeviceResponseVerificationResult> {
    const deviceResponse =
      options.deviceResponse instanceof DeviceResponse
        ? options.deviceResponse
        : DeviceResponse.decode(options.deviceResponse)

    return deviceResponse.verify(options, ctx)
  }

  /**
   * Match a device response against the device request it answers, without verifying it.
   *
   * The ISO mdoc DC API protocol (`org-iso-mdoc`) has no query language such as DCQL to express
   * which claims a response has to contain, so the device request itself is the query: this reports
   * per doc request, per document and per check (docType and claims) whether the response satisfies
   * it.
   *
   * `Verifier.verifyDeviceResponse` runs the same match as part of verification when a
   * `deviceRequest` is passed, reporting it through `onCheck` and returning it as
   * `deviceRequestMatch`. Use this method to match a response without verifying it.
   *
   * Applies the same rules as `Holder.matchDeviceRequest`, with which a holder selects the
   * credentials to answer the device request with.
   */
  public static matchDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    deviceResponse: Uint8Array | DeviceResponse
    /**
     * Per doc request the elements that are optional or that may be answered from `deviceSigned`.
     * By default every requested element is required and must be issuer-signed.
     */
    matchOptions?: DeviceRequestMatchOptions
  }): DeviceRequestMatchResult {
    return matchDeviceRequest({
      matchOptions: options.matchOptions,
      deviceRequest:
        options.deviceRequest instanceof DeviceRequest
          ? options.deviceRequest
          : DeviceRequest.decode(options.deviceRequest),
      deviceResponse:
        options.deviceResponse instanceof DeviceResponse
          ? options.deviceResponse
          : DeviceResponse.decode(options.deviceResponse),
    })
  }
}
