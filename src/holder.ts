import { base64url } from 'jose'
import type { MdocContext } from './context'
import type { CoseKey } from './cose'
import {
  DeviceRequest,
  DeviceResponse,
  type Document,
  IssuerSigned,
  type PresentationDefinition,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'

export class Holder {
  /**
   *
   * string should be base64url encoded as defined in openid4vci Draft 15
   *
   */
  public static async validateIssuerSigned(
    options: {
      issuerSigned: Uint8Array | string | IssuerSigned
      verificationCallback?: VerificationCallback
      now?: Date
      disableCertificateChainValidation?: boolean
      trustedCertificates?: Array<Uint8Array>
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const issuerSigned =
      typeof options.issuerSigned === 'string'
        ? IssuerSigned.decode(base64url.decode(options.issuerSigned))
        : options.issuerSigned instanceof Uint8Array
          ? IssuerSigned.decode(options.issuerSigned)
          : options.issuerSigned

    await issuerSigned.issuerAuth.validate(options, ctx)
  }

  public static async validateDeviceRequest(
    options: {
      deviceRequest: Uint8Array | DeviceRequest
      sessionTranscript: Uint8Array | SessionTranscript
      verificationCallback?: VerificationCallback
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
      await docRequest.readerAuth?.validate(
        {
          readerAuthentication: {
            itemsRequest: docRequest.itemsRequest,
            sessionTranscript,
          },
          verificationCallback: options.verificationCallback,
        },
        ctx
      )
    }
  }

  public static async createDeviceResponseForDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript
      documents: Array<Document>
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    context: Pick<MdocContext, 'cose' | 'crypto'>
  ) {
    return await DeviceResponse.createWithDeviceRequest(options, context)
  }

  public static async createDeviceResponseForPresentationDefinition(
    options: {
      presentationDefinition: PresentationDefinition
      sessionTranscript: SessionTranscript
      documents: Array<Document>
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    context: Pick<MdocContext, 'cose' | 'crypto'>
  ) {
    return await DeviceResponse.createWithPresentationDefinition(options, context)
  }
}
