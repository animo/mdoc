import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { type CoseKey, Header, ProtectedHeaders, UnprotectedHeaders } from '../../cose'
import { base64url } from '../../utils'
import { findIssuerSigned } from '../../utils/findIssuerSigned'
import { limitDisclosureToDeviceRequestNameSpaces } from '../../utils/limitDisclosure'
import { verifyDocRequestsWithIssuerSigned } from '../../utils/verifyDocRequestsWithIssuerSigned'
import { defaultVerificationCallback, type VerificationCallback } from '../check-callback'
import { EitherSignatureOrMacMustBeProvidedError } from '../errors'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import { Document, type DocumentStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import { IssuerSigned } from './issuer-signed'
import { SessionTranscript } from './session-transcript'

export type DeviceResponseStructure = {
  version: string
  documents?: Array<DocumentStructure>
  documentErrors?: Array<DocumentErrorStructure>
  status: number
}

export type DeviceResponseOptions = {
  version?: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status?: number
}

export class DeviceResponse extends CborStructure {
  public version: string
  public documents?: Array<Document>
  public documentErrors?: Array<DocumentError>
  public status: number

  public constructor(options: DeviceResponseOptions) {
    super()
    this.version = options.version ?? '1.0'
    this.documents = options.documents
    this.documentErrors = options.documentErrors
    this.status = options.status ?? 0
  }

  public encodedStructure(): DeviceResponseStructure {
    const structure: Partial<DeviceResponseStructure> = {
      version: this.version,
    }

    if (this.documents) {
      structure.documents = this.documents?.map((d) => d.encodedStructure())
    }

    if (this.documentErrors) {
      structure.documentErrors = this.documentErrors?.map((d) => d.encodedStructure())
    }

    structure.status = this.status

    return structure as DeviceResponseStructure
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceResponseStructure | Map<unknown, unknown>
  ): DeviceResponse {
    let structure = encodedStructure as DeviceResponseStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DeviceResponseStructure
    }

    return new DeviceResponse({
      version: structure.version,
      status: structure.status,
      documents: structure.documents?.map(Document.fromEncodedStructure),
      documentErrors: structure.documentErrors?.map(DocumentError.fromEncodedStructure),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceResponse {
    const structure = cborDecode<DeviceResponseStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return DeviceResponse.fromEncodedStructure(structure)
  }

  public async verify(
    options: {
      deviceRequest?: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>
  ) {
    const onCheck = options.onCheck ?? defaultVerificationCallback

    onCheck({
      status: this.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: !this.documents || (this.documents && this.documents.length > 0) ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    for (const document of this.documents ?? []) {
      await document.issuerSigned.issuerAuth.verify(
        {
          disableCertificateChainValidation: options.disableCertificateChainValidation,
          now: options.now,
          trustedCertificates: options.trustedCertificates,
          verificationCallback: onCheck,
        },
        ctx
      )

      await document.deviceSigned.deviceAuth.verify(
        {
          document,
          ephemeralMacPrivateKey: options.ephemeralReaderKey,
          sessionTranscript:
            options.sessionTranscript instanceof SessionTranscript
              ? options.sessionTranscript
              : SessionTranscript.decode(options.sessionTranscript),
          verificationCallback: onCheck,
        },
        ctx
      )

      await document.issuerSigned.verify({ verificationCallback: onCheck }, ctx)
    }

    if (options.deviceRequest?.docRequests && this.documents) {
      try {
        verifyDocRequestsWithIssuerSigned(
          options.deviceRequest.docRequests,
          this.documents.map((d) => d.issuerSigned)
        )
        onCheck({
          status: 'PASSED',
          check: 'Device Response did match the Device Request',
          category: 'DOCUMENT_FORMAT',
        })
      } catch (e) {
        onCheck({
          status: 'FAILED',
          check: `Device Response did not match the Device Request: ${(e as Error).message}`,
          category: 'DOCUMENT_FORMAT',
        })
      }
    }
  }

  public get encodedForOid4Vp() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vp(encoded: string): DeviceResponse {
    return DeviceResponse.decode(base64url.decode(encoded))
  }

  private static async create(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
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

    const documents = await Promise.all(
      options.deviceRequest.docRequests.map(async (docRequest) => {
        const issuerSigned = findIssuerSigned(options.issuerSigned, docRequest.itemsRequest.docType)
        const disclosedIssuerNamespace = limitDisclosureToDeviceRequestNameSpaces(issuerSigned, docRequest)

        const docType = docRequest.itemsRequest.docType

        const deviceNamespaces = options.deviceNamespaces ?? new DeviceNamespaces({ deviceNamespaces: new Map() })

        const deviceAuthenticationBytes = new DeviceAuthentication({
          sessionTranscript: options.sessionTranscript,
          docType,
          deviceNamespaces,
        }).encode({ asDataItem: true })

        const unprotectedHeaders = signingKey.keyId
          ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyId, signingKey.keyId]]) })
          : new UnprotectedHeaders({})

        const protectedHeaders = new ProtectedHeaders({
          protectedHeaders: new Map([[Header.Algorithm, signingKey.algorithm]]),
        })

        const deviceAuthOptions: DeviceAuthOptions = {}
        if (useSignature) {
          const deviceSignature = new DeviceSignature({
            unprotectedHeaders,
            protectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          await deviceSignature.addSignature({ signingKey }, ctx)

          deviceAuthOptions.deviceSignature = deviceSignature
        } else {
          const deviceMac = new DeviceMac({
            protectedHeaders,
            unprotectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          const ephemeralKey = options.mac?.ephemeralKey
          if (!ephemeralKey) throw new Error('Ephemeral key is missing')

          await deviceMac.addTag(
            {
              privateKey: signingKey,
              ephemeralKey: ephemeralKey,
              sessionTranscript: options.sessionTranscript,
            },
            ctx
          )

          deviceAuthOptions.deviceMac = deviceMac
        }

        return new Document({
          docType,
          issuerSigned: new IssuerSigned({
            issuerNamespaces: disclosedIssuerNamespace,
            issuerAuth: issuerSigned.issuerAuth,
          }),
          deviceSigned: new DeviceSigned({
            deviceNamespaces,
            deviceAuth: new DeviceAuth(deviceAuthOptions),
          }),
        })
      })
    )

    return new DeviceResponse({
      documents,
    })
  }

  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    return await DeviceResponse.create(options, ctx)
  }
}
