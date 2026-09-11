import {
  type CoseKey,
  Curve,
  KeyType,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  UnprotectedHeaders,
} from '@owf/cose'
import { base64url } from '@owf/identity-common'
import { z } from 'zod'
import { HpkeSuiteId, type MdocContext } from './context'
import {
  type DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  type DeviceResponseVerificationResult,
  DocRequest,
  EncryptedResponse,
  EncryptedResponseData,
  EncryptionInfo,
  EncryptionParameters,
  HpkeNotSupportedError,
  InvalidDcApiRequestError,
  InvalidDcApiResponseError,
  InvalidEncryptionInfoError,
  type IssuerSigned,
  ItemsRequest,
  MissingOriginError,
  ReaderAuth,
  ReaderAuthentication,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'
import type { DeviceRequestMatchOptions } from './utils/matchDeviceRequest'

/**
 * DC API protocol identifier for ISO/IEC TS 18013-7:2025 Annex C.
 */
export const isoMdocDcApiProtocol = 'org-iso-mdoc'

/**
 * The only HPKE suite Annex C allows (C.4).
 */
export const isoMdocDcApiHpkeSuite = HpkeSuiteId.DhkemP256HkdfSha256HkdfSha256Aes128Gcm

/**
 * Minimum nonce entropy required by C.2.
 */
const minimumNonceLength = 16

/**
 * Base64url-no-pad, as Annex C encodes every member of the request and response payloads.
 */
const base64UrlSchema = z.base64url().min(1)

/**
 * Request payload exchanged over the DC API (C.2). Both members are base64url-no-pad encoded CBOR.
 */
export const isoMdocDcApiRequestSchema = z.object({
  deviceRequest: base64UrlSchema,
  encryptionInfo: base64UrlSchema,
})
export type IsoMdocDcApiRequest = z.infer<typeof isoMdocDcApiRequestSchema>

/**
 * Response payload returned over the DC API (C.3), base64url-no-pad encoded CBOR.
 */
export const isoMdocDcApiResponseSchema = z.object({
  response: base64UrlSchema,
})
export type IsoMdocDcApiResponse = z.infer<typeof isoMdocDcApiResponseSchema>

/**
 * The response as it may be handed to {@link IsoMdocDcApi.decryptResponse}, normalized to the
 * base64url `response` string.
 */
const isoMdocDcApiResponseInputSchema = z.union([
  base64UrlSchema,
  isoMdocDcApiResponseSchema.transform(({ response }) => response),
])

export type IsoMdocDcApiParsedDocRequest = {
  docRequest: DocRequest
  docType: string
  namespaces: Map<string, Map<string, boolean>>
  /**
   * Reader auth is optional in Annex C. `false` means the request carried no reader signature at
   * all — not that verification failed (an invalid signature surfaces through the verification
   * callback).
   */
  readerAuthenticated: boolean
  readerCertificateChain?: Array<Uint8Array>
}

export type IsoMdocDcApiParsedRequest = {
  origin: string
  deviceRequest: DeviceRequest
  encryptionInfo: EncryptionInfo
  encryptionInfoBase64Url: string
  sessionTranscript: SessionTranscript
  docRequests: Array<IsoMdocDcApiParsedDocRequest>
}

export type IsoMdocDcApiCreatedRequest = {
  request: IsoMdocDcApiRequest
  deviceRequest: DeviceRequest
  encryptionInfo: EncryptionInfo
  sessionTranscript?: SessionTranscript
}

/**
 * ISO/IEC TS 18013-7:2025 Annex C (`org-iso-mdoc`) request and response handling.
 *
 * The HPKE operations are provided by the caller through `ctx.crypto.hpke`, so this package stays
 * free of a cryptographic backend.
 */
export class IsoMdocDcApi {
  /**
   * Build an Annex C request (verifier side).
   *
   * When `readerAuth` is provided each doc request is signed over a `ReaderAuthentication`
   * structure that binds the session transcript, and therefore a single `origin` — a signed request
   * can only be used against the origin it was created for.
   */
  public static async createRequest(
    options: {
      docRequests: Array<{
        docType: string
        namespaces: Record<string, Record<string, boolean>> | Map<string, Map<string, boolean>>
      }>
      /**
       * Public key the response is encrypted to. Must be an EC P-256 key.
       */
      recipientPublicKey: CoseKey
      /**
       * At least 16 bytes of entropy, fresh per transaction (C.2). Generated when omitted.
       */
      nonce?: Uint8Array
      version?: string
      readerAuth?: {
        signingKey: CoseKey
        certificateChain: Array<Uint8Array>
        origin: string
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ): Promise<IsoMdocDcApiCreatedRequest> {
    const nonce = options.nonce ?? ctx.crypto.random(minimumNonceLength)
    if (nonce.length < minimumNonceLength) {
      throw new InvalidEncryptionInfoError(`Nonce must be at least ${minimumNonceLength} bytes`)
    }
    assertP256PublicKey(options.recipientPublicKey)

    const encryptionInfo = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({ nonce, recipientPublicKey: options.recipientPublicKey }),
    })
    const encryptionInfoBase64Url = encryptionInfo.toBase64Url()

    // The transcript only depends on the encryption info and the origin, so it can be computed
    // before the doc requests are signed.
    const sessionTranscript = options.readerAuth
      ? await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin: options.readerAuth.origin }, ctx)
      : undefined

    const docRequests = await Promise.all(
      options.docRequests.map(async ({ docType, namespaces }) => {
        const itemsRequest = ItemsRequest.create({ docType, namespaces })

        if (!options.readerAuth || !sessionTranscript) {
          return DocRequest.create({ itemsRequest })
        }

        const { signingKey, certificateChain } = options.readerAuth
        const unprotectedHeaders = UnprotectedHeaders.create({})
        unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.X5Chain, certificateChain)

        const readerAuth = (await ReaderAuth.create({
          protectedHeaders: ProtectedHeaders.create({
            protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, signingKey.algorithm]]),
          }),
          unprotectedHeaders,
          payload: null,
        }).sign(
          {
            signingKey,
            detachedPayload: ReaderAuthentication.create({ sessionTranscript, itemsRequest }).encode({
              asDataItem: true,
            }),
          },
          { sign: ctx.cose.sign1.sign }
        )) as ReaderAuth

        return DocRequest.create({ itemsRequest, readerAuth })
      })
    )

    const deviceRequest = DeviceRequest.create({ version: options.version, docRequests })

    return {
      request: {
        deviceRequest: base64url.encode(deviceRequest.encode()),
        encryptionInfo: encryptionInfoBase64Url,
      },
      deviceRequest,
      encryptionInfo,
      sessionTranscript,
    }
  }

  /**
   * Parse and validate an Annex C request (wallet side), and verify reader auth where present.
   *
   * `origin` must be the origin the platform provided; C.5 requires the mdoc to abort when no
   * origin was received.
   */
  public static async parseRequest(
    options: {
      request: IsoMdocDcApiRequest
      origin: string | undefined
      /**
       * Trust anchors for reader certificate chains. When omitted, reader signatures are still
       * verified but chain trust is not established.
       */
      trustedReaderCertificates?: Array<Uint8Array>
      verificationCallback?: VerificationCallback
      now?: Date
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose' | 'x509'>
  ): Promise<IsoMdocDcApiParsedRequest> {
    const { origin } = options
    if (!origin) throw new MissingOriginError('No origin was provided by the DC API')

    // The request is handed to us by the platform, so validate its shape before decoding anything.
    const request = parseOrThrow(isoMdocDcApiRequestSchema, options.request, InvalidDcApiRequestError, 'DC API request')

    const encryptionInfoBase64Url = request.encryptionInfo
    const encryptionInfo = EncryptionInfo.fromBase64Url(encryptionInfoBase64Url)

    if (encryptionInfo.nonce.length < minimumNonceLength) {
      throw new InvalidEncryptionInfoError(`Nonce must be at least ${minimumNonceLength} bytes`)
    }
    assertP256PublicKey(encryptionInfo.recipientPublicKey)

    const deviceRequest = DeviceRequest.decode(base64url.decode(request.deviceRequest))
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, ctx)

    const docRequests: Array<IsoMdocDcApiParsedDocRequest> = []
    for (const docRequest of deviceRequest.docRequests) {
      const { readerAuth } = docRequest

      if (readerAuth) {
        await readerAuth.verify(
          {
            readerAuthentication: { itemsRequest: docRequest.itemsRequest, sessionTranscript },
            verificationCallback: options.verificationCallback,
            trustedCertificates: options.trustedReaderCertificates,
            now: options.now,
          },
          ctx
        )
      }

      docRequests.push({
        docRequest,
        docType: docRequest.itemsRequest.docType,
        namespaces: docRequest.itemsRequest.namespaces,
        readerAuthenticated: !!readerAuth,
        readerCertificateChain: readerAuth?.certificateChain,
      })
    }

    return {
      origin,
      deviceRequest,
      encryptionInfo,
      encryptionInfoBase64Url,
      sessionTranscript,
      docRequests,
    }
  }

  /**
   * Create the encrypted Annex C response (wallet side).
   *
   * Device auth uses `deviceSignature`; the MAC variant has no key-agreement channel in the DC API
   * flow.
   */
  public static async createResponse(
    options: {
      parsedRequest: IsoMdocDcApiParsedRequest
      documents: Array<{
        issuerSigned: IssuerSigned
        deviceKey: CoseKey
        /**
         * Index into `parsedRequest.docRequests` of the doc request this document answers.
         */
        docRequestIndex: number
        /**
         * The requested elements to disclose, per namespace. Defaults to every element the doc
         * request asks for.
         */
        elements?: Record<string, Array<string>>
        /**
         * Elements to disclose device-signed. Every requested element that is not issuer-signed,
         * but that the device key is authorized for in the MSO, has to be provided here.
         */
        deviceNamespaces?: DeviceNamespaces
      }>
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ): Promise<IsoMdocDcApiResponse> {
    const hpke = assertHpke(ctx)
    const { parsedRequest } = options

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest: parsedRequest.deviceRequest,
        sessionTranscript: parsedRequest.sessionTranscript,
        documents: options.documents.map((document) => ({
          docRequestIndex: document.docRequestIndex,
          issuerSigned: document.issuerSigned,
          elements: document.elements,
          deviceNamespaces: document.deviceNamespaces,
          signature: { signingKey: document.deviceKey },
        })),
      },
      ctx
    )

    const { enc, ciphertext } = await hpke.seal({
      suite: isoMdocDcApiHpkeSuite,
      recipientPublicKey: parsedRequest.encryptionInfo.recipientPublicKey,
      // C.4: `info` is the session transcript encoded as a bare CBOR array, not as
      // SessionTranscriptBytes (tag 24). `aad` is empty.
      info: parsedRequest.sessionTranscript.encode(),
      plaintext: deviceResponse.encode(),
    })

    const encryptedResponse = EncryptedResponse.create({
      encryptedResponseData: EncryptedResponseData.create({ enc, ciphertext }),
    })

    return { response: encryptedResponse.toBase64Url() }
  }

  /**
   * Decrypt an Annex C response (verifier side) without verifying the documents.
   *
   * Decryption is bound to the origin through the session transcript, so a response relayed from a
   * different origin fails here.
   */
  public static async decryptResponse(
    options: {
      response: IsoMdocDcApiResponse | string
      origin: string
      /**
       * The base64url `encryptionInfo` exactly as it was sent to the wallet.
       */
      encryptionInfo: string
      /**
       * The recipient key whose public part was sent to the wallet in `encryptionInfo`. When the
       * private key is held by a key management system, pass the public key carrying the `keyId`
       * the `ctx.crypto.hpke.open` implementation resolves the private key with.
       */
      recipientKey: CoseKey
    },
    ctx: Pick<MdocContext, 'crypto'>
  ): Promise<{ deviceResponse: DeviceResponse; sessionTranscript: SessionTranscript }> {
    const hpke = assertHpke(ctx)
    if (!options.origin) throw new MissingOriginError('No origin was provided by the DC API')

    // The response comes from the wallet, so validate its shape before decoding anything.
    const response = parseOrThrow(
      isoMdocDcApiResponseInputSchema,
      options.response,
      InvalidDcApiResponseError,
      'DC API response'
    )

    const encryptedResponse = EncryptedResponse.fromBase64Url(response)

    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url: options.encryptionInfo, origin: options.origin },
      ctx
    )

    const plaintext = await hpke.open({
      suite: isoMdocDcApiHpkeSuite,
      recipientKey: options.recipientKey,
      enc: encryptedResponse.enc,
      info: sessionTranscript.encode(),
      ciphertext: encryptedResponse.ciphertext,
    })

    return { deviceResponse: DeviceResponse.decode(plaintext), sessionTranscript }
  }

  /**
   * Decrypt and verify an Annex C response (verifier side).
   */
  public static async verifyResponse(
    options: {
      response: IsoMdocDcApiResponse | string
      origin: string
      encryptionInfo: string
      recipientKey: CoseKey
      deviceRequest?: DeviceRequest
      /**
       * Options to match the response against `deviceRequest` with: per doc request the elements
       * that are optional or that may be answered from `deviceSigned`. By default every requested
       * element is required and must be issuer-signed.
       */
      deviceRequestMatchOptions?: DeviceRequestMatchOptions
      trustedCertificates: Array<{ issuance: Array<Uint8Array>; status?: Array<Uint8Array> }>
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      onCheck?: VerificationCallback
      now?: Date
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose' | 'x509' | 'fetch'>
  ): Promise<{
    deviceResponse: DeviceResponse
    verificationResult: DeviceResponseVerificationResult
  }> {
    const { deviceResponse, sessionTranscript } = await IsoMdocDcApi.decryptResponse(options, ctx)

    const verificationResult = await deviceResponse.verify(
      {
        deviceRequest: options.deviceRequest,
        deviceRequestMatchOptions: options.deviceRequestMatchOptions,
        sessionTranscript,
        trustedCertificates: options.trustedCertificates,
        disableCertificateChainValidation: options.disableCertificateChainValidation,
        disableStatusValidation: options.disableStatusValidation,
        onCheck: options.onCheck,
        now: options.now,
        skewSeconds: options.skewSeconds,
      },
      ctx
    )

    return { deviceResponse, verificationResult }
  }
}

function assertHpke(ctx: Pick<MdocContext, 'crypto'>) {
  const { hpke } = ctx.crypto
  if (!hpke) {
    throw new HpkeNotSupportedError('The mdoc context does not provide HPKE support')
  }

  if (!hpke.suites.includes(isoMdocDcApiHpkeSuite)) {
    throw new HpkeNotSupportedError(`The mdoc context does not support HPKE suite '${isoMdocDcApiHpkeSuite}'`)
  }

  return hpke
}

function assertP256PublicKey(coseKey: CoseKey) {
  if (coseKey.keyType !== KeyType.Ec || coseKey.curve !== Curve['P-256']) {
    throw new InvalidEncryptionInfoError('Recipient public key must be an EC P-256 key')
  }
}

/**
 * Parse untrusted input, surfacing a validation failure as the DC API error for that payload.
 */
function parseOrThrow<Schema extends z.ZodType>(
  schema: Schema,
  data: unknown,
  ErrorClass: new (message: string) => Error,
  description: string
): z.output<Schema> {
  const result = schema.safeParse(data)
  if (!result.success) {
    throw new ErrorClass(`Invalid ${description}: ${z.prettifyError(result.error)}`)
  }

  return result.data
}
