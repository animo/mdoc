import {
  CborStructure,
  type CoseKey,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  TypedMap,
  typedMap,
  UnprotectedHeaders,
} from '@owf/cose'
import { base64url, stringToBytes } from '@owf/identity-common'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import {
  describeUnauthorizedDeviceSignedElements,
  findUnauthorizedDeviceSignedElements,
} from '../../utils/keyAuthorizations'
import { limitDisclosureToDeviceRequestNameSpaces } from '../../utils/limitDisclosure'
import {
  type DeviceRequestElementOptions,
  type DeviceRequestMatchResult,
  matchDeviceRequest,
  reportDeviceRequestMatch,
} from '../../utils/matchDeviceRequest'
import { defaultVerificationCallback, type VerificationCallback } from '../check-callback'
import { DeviceKeyNotAuthorizedError, EitherSignatureOrMacMustBeProvidedError } from '../errors'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import type { DocRequest } from './doc-request'
import { Document, type DocumentEncodedStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import type { IssuerAuthVerificationResult } from './issuer-auth'
import { IssuerSigned } from './issuer-signed'
import type { SessionTranscript } from './session-transcript'

const deviceResponseEncodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.unknown()).exactOptional()],
  ['documentErrors', z.array(z.unknown()).exactOptional()],
] as const)

const deviceResponseDecodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.instanceof(Document)).exactOptional()],
  ['documentErrors', z.array(z.instanceof(DocumentError)).exactOptional()],
] as const)

export type DeviceResponseEncodedStructure = z.input<typeof deviceResponseEncodedSchema>
export type DeviceResponseDecodedStructure = z.output<typeof deviceResponseDecodedSchema>

export type DeviceResponseOptions = {
  version?: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status?: number
}

export type DocumentVerificationResult = IssuerAuthVerificationResult & { document: Document }

export type DeviceResponseVerificationResult = {
  /**
   * One entry per document in the device response, in response order.
   */
  documents: Array<DocumentVerificationResult>
  /**
   * How the response matches the device request, per doc request and per requested element. Only
   * present when `deviceRequest` was provided.
   */
  deviceRequestMatch?: DeviceRequestMatchResult
}

/**
 * A single document to disclose in a device response, authenticated with either a device signature
 * or a device MAC.
 */
export type DeviceResponseDocumentOptions = {
  issuerSigned: IssuerSigned
  /**
   * Index into `deviceRequest.docRequests` of the doc request this document answers.
   */
  docRequestIndex: number
  deviceNamespaces?: DeviceNamespaces
  signature?: {
    signingKey: CoseKey
  }
  mac?: {
    ephemeralKey: CoseKey
    signingKey: CoseKey
  }
}

export class DeviceResponse extends CborStructure<DeviceResponseEncodedStructure, DeviceResponseDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceResponseEncodedSchema.in, deviceResponseDecodedSchema.out, {
      decode: (input) => {
        const map = TypedMap.fromMap(input) as DeviceResponseDecodedStructure

        if (input.has('documents')) {
          map.set(
            'documents',
            (input.get('documents') as unknown[]).map((d) =>
              Document.fromEncodedStructure(d as DocumentEncodedStructure)
            )
          )
        }

        if (input.has('documentErrors')) {
          map.set(
            'documentErrors',
            (input.get('documentErrors') as unknown[]).map((d) =>
              DocumentError.fromEncodedStructure(d as DocumentErrorStructure)
            )
          )
        }

        return map
      },
      encode: (output) => {
        const map: Map<unknown, unknown> = output.toMap()

        const documents = output.get('documents')
        if (documents !== undefined) {
          map.set(
            'documents',
            documents.map((d) => d.encodedStructure)
          )
        }

        const documentErrors = output.get('documentErrors')
        if (documentErrors !== undefined) {
          map.set(
            'documentErrors',
            documentErrors.map((d) => d.encodedStructure)
          )
        }

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get documents() {
    return this.structure.get('documents')
  }

  public get documentErrors() {
    return this.structure.get('documentErrors')
  }

  public get status() {
    return this.structure.get('status')
  }

  public async verify(
    options: {
      deviceRequest?: DeviceRequest
      /**
       * Per-element match options for `deviceRequest`, for elements that are optional or that may
       * be answered from `deviceSigned`. Every element not named here is required and must be
       * issuer-signed.
       */
      deviceRequestElements?: DeviceRequestElementOptions
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
    const onCheck = options.onCheck ?? defaultVerificationCallback

    const version = this.structure.get('version')
    onCheck({
      status: version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    const documents = this.structure.get('documents')
    onCheck({
      status: !documents || documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    // 18013-5 8.3.2.1.2.3 Table 8: an mdoc returning a status other than 0 must not return documents.
    const status = this.structure.get('status')
    onCheck({
      status: status === 0 || !documents?.length ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents when the status is not 0.',
      category: 'DOCUMENT_FORMAT',
      reason:
        status !== 0 && documents?.length
          ? `Device Response has status ${status} but returned ${documents.length} document(s)`
          : undefined,
    })

    const documentResults: Array<DocumentVerificationResult> = []
    for (const document of documents ?? []) {
      await document.deviceSigned.deviceAuth.verify(
        {
          document,
          ephemeralMacPrivateKey: options.ephemeralReaderKey,
          sessionTranscript: options.sessionTranscript,
          verificationCallback: onCheck,
        },
        ctx
      )

      const { trustedIssuanceChain, statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain } =
        await document.issuerSigned.verify(
          {
            verificationCallback: onCheck,
            disableCertificateChainValidation: options.disableCertificateChainValidation,
            now: options.now,
            trustedCertificates: options.trustedCertificates,
            skewSeconds: options.skewSeconds,
            disableStatusValidation: options.disableStatusValidation,
          },
          ctx
        )
      documentResults.push({
        trustedIssuanceChain,
        statusList,
        trustedStatusListChain,
        identifierList,
        trustedIdentifierListChain,
        document,
      })
    }

    let deviceRequestMatch: DeviceRequestMatchResult | undefined
    if (options.deviceRequest) {
      deviceRequestMatch = matchDeviceRequest({
        deviceRequest: options.deviceRequest,
        deviceResponse: this,
        elements: options.deviceRequestElements,
      })
      reportDeviceRequestMatch(deviceRequestMatch, onCheck)
    }

    return { documents: documentResults, deviceRequestMatch }
  }

  public get encodedForOid4Vp() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vp(encoded: string): DeviceResponse {
    return DeviceResponse.decode(base64url.decode(encoded))
  }

  /**
   * Create a single disclosed `Document` for one `DocRequest`, authenticated with either a
   * device signature or a device MAC.
   */
  private static async createDocument(
    options: {
      docRequest: DocRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: IssuerSigned
      deviceNamespaces?: DeviceNamespaces
      signature?: {
        signingKey: CoseKey
      }
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const useMac = !!options.mac
    const useSignature = !!options.signature
    if (useMac === useSignature) throw new EitherSignatureOrMacMustBeProvidedError()

    const signingKey = useSignature ? options.signature?.signingKey : options.mac?.signingKey
    if (!signingKey) throw new Error('Signing key is missing')

    const { docRequest } = options
    const docType = docRequest.itemsRequest.docType
    const disclosedIssuerNamespace = limitDisclosureToDeviceRequestNameSpaces(options.issuerSigned, docRequest)

    const deviceNamespaces = options.deviceNamespaces ?? DeviceNamespaces.create({ deviceNamespaces: new Map() })

    // 18013-5 9.1.3.4 binds the mdoc as well as the mdoc reader, so refuse to authenticate elements
    // the device key is not authorized for rather than emit a response every reader must reject.
    const unauthorized = findUnauthorizedDeviceSignedElements({
      deviceNamespaces,
      keyAuthorizations: options.issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo.keyAuthorizations,
    })
    if (unauthorized.length > 0) {
      throw new DeviceKeyNotAuthorizedError(describeUnauthorizedDeviceSignedElements(unauthorized))
    }

    const deviceAuthenticationBytes = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      docType,
      deviceNamespaces,
    }).encode({ asDataItem: true })

    const unprotectedHeaders = UnprotectedHeaders.create({})
    if (signingKey.keyId) {
      // COSE label 4 (kid) is a bstr per RFC 8152; UTF-8 encode
      // the text form at the header boundary.
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, stringToBytes(signingKey.keyId))
    }

    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, signingKey.algorithm]]),
    })

    const deviceAuthOptions: DeviceAuthOptions = {}
    if (useSignature) {
      const deviceSignature = await DeviceSignature.create({
        unprotectedHeaders,
        protectedHeaders,
        payload: null,
      }).sign({ signingKey, detachedPayload: deviceAuthenticationBytes }, { sign: ctx.cose.sign1.sign })

      deviceAuthOptions.deviceSignature = deviceSignature
    } else {
      const ephemeralKey = options.mac?.ephemeralKey
      if (!ephemeralKey) throw new Error('Ephemeral key is missing')

      const deviceMac = DeviceMac.create({
        protectedHeaders,
        unprotectedHeaders,
        payload: null,
      })

      const macKey = await deviceMac.createDeviceMacKey(
        {
          publicKey: ephemeralKey,
          privateKey: signingKey,
          sessionTranscript: options.sessionTranscript,
        },
        ctx
      )

      await deviceMac.authenticate({ key: macKey, detachedPayload: deviceAuthenticationBytes }, ctx.cose.mac0)

      deviceAuthOptions.deviceMac = deviceMac
    }

    return Document.create({
      docType,
      issuerSigned: IssuerSigned.create({
        issuerNamespaces: disclosedIssuerNamespace,
        issuerAuth: options.issuerSigned.issuerAuth,
      }),
      deviceSigned: DeviceSigned.create({
        deviceNamespaces,
        deviceAuth: DeviceAuth.create(deviceAuthOptions),
      }),
    })
  }

  private static fromDocuments(documents: Array<Document>) {
    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', '1.0'],
      ['status', 0],
      ['documents', documents],
    ])

    return DeviceResponse.fromDecodedStructure(map)
  }

  private static findDocRequest(deviceRequest: DeviceRequest, docRequestIndex: number): DocRequest {
    const docRequest = deviceRequest.docRequests[docRequestIndex]
    if (!docRequest) throw new Error(`No doc request found at index ${docRequestIndex}`)

    return docRequest
  }

  /**
   * Create a device response for a device request.
   *
   * Every document brings its own device key and, optionally, its own device namespaces, and names
   * the doc request it answers through `docRequestIndex`, so a request may also be answered
   * partially.
   */
  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      documents: Array<DeviceResponseDocumentOptions>
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const documents = await Promise.all(
      options.documents.map((document) =>
        DeviceResponse.createDocument(
          {
            docRequest: DeviceResponse.findDocRequest(options.deviceRequest, document.docRequestIndex),
            sessionTranscript: options.sessionTranscript,
            issuerSigned: document.issuerSigned,
            deviceNamespaces: document.deviceNamespaces,
            signature: document.signature,
            mac: document.mac,
          },
          ctx
        )
      )
    )

    return DeviceResponse.fromDocuments(documents)
  }

  public static createSimple(options: DeviceResponseOptions): DeviceResponse {
    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['status', options.status ?? 0],
    ])

    if (options.documents !== undefined) {
      map.set('documents', options.documents)
    }

    if (options.documentErrors !== undefined) {
      map.set('documentErrors', options.documentErrors)
    }

    return this.fromDecodedStructure(map)
  }
}
