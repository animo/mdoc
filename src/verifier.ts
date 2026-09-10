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
  type DeviceRequestElementOptions,
  type DeviceRequestMatchResult,
  matchDeviceRequest,
} from './utils/matchDeviceRequest.js'

export class Verifier {
  public static async verifyDeviceResponse(
    options: {
      deviceRequest?: DeviceRequest
      /**
       * Per-element match options for `deviceRequest`, for elements that are optional or that may
       * be answered from `deviceSigned`. Every element not named here is required and must be
       * issuer-signed.
       */
      deviceRequestElements?: DeviceRequestElementOptions
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
   * per doc request, per document and per requested element whether the response satisfies it.
   *
   * `Verifier.verifyDeviceResponse` runs the same match as part of verification when a
   * `deviceRequest` is passed, reporting it through `onCheck` and returning it as
   * `deviceRequestMatch`. Use this method to match a response without verifying it.
   */
  public static matchDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    deviceResponse: Uint8Array | DeviceResponse
    /**
     * Per-element match options, for elements that are optional or that may be answered from
     * `deviceSigned`. Every element not named here is required and must be issuer-signed.
     */
    elements?: DeviceRequestElementOptions
  }): DeviceRequestMatchResult {
    return matchDeviceRequest({
      elements: options.elements,
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
