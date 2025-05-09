import type { MdocContext } from './context.js'
import type { CoseKey } from './cose/index.js'
import type { VerificationCallback } from './mdoc/check-callback.js'
import { DeviceResponse, type SessionTranscript } from './mdoc/index.js'

export class Verifier {
  /**
   *
   *
   * @todo should this check if it is also compatible with the device /pex request?
   *
   */
  public static async verifyDeviceResponse(
    options: {
      deviceResponse: Uint8Array | DeviceResponse
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>
  ) {
    const deviceResponse =
      options.deviceResponse instanceof DeviceResponse
        ? options.deviceResponse
        : DeviceResponse.decode(options.deviceResponse)

    await deviceResponse.validate(options, ctx)
  }
}
