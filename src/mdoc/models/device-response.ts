import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { CoseInvalidAlgorithmError, type CoseKey, Header, ProtectedHeaders, UnprotectedHeaders } from '../../cose'
import { type VerificationCallback, defaultVerificationCallback } from '../check-callback'
import { EitherSignatureOrMacMustBeProvidedError } from '../errors'
import { Verifier } from '../verifier'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import type { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import type { DocRequest } from './doc-request'
import { Document, type DocumentStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import type { IssuerSigned } from './issuer-signed'
import {
  findMdocMatchingDocType,
  limitDisclosureToDeviceRequestNameSpaces,
  limitDisclosureToInputDescriptor,
} from './pex-limit-disclosure'
import type { InputDescriptor, PresentationDefinition } from './presentation-definition'
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

  public async validate(
    options: {
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
      await document.issuerSigned.issuerAuth.validate(
        {
          disableCertificateChainValidation: options.disableCertificateChainValidation,
          now: options.now,
          trustedCertificates: options.trustedCertificates,
          verificationCallback: onCheck,
        },
        ctx
      )

      await document.deviceSigned.deviceAuth.validate(
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

      // TODO: move
      await new Verifier().verifyData({ document, verificationCallback: onCheck }, ctx)
    }
  }

  private static async create(
    limitDisclosureCb:
      | ((issuerSigned: IssuerSigned, inputDescriptor: InputDescriptor) => DeviceNamespaces)
      | ((issuerSigned: IssuerSigned, docRequest: DocRequest) => DeviceNamespaces),
    options: {
      inputDescriptorsOrRequests: Array<InputDescriptor> | Array<DocRequest>
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
    context: { crypto: MdocContext['crypto']; cose: MdocContext['cose'] }
  ) {
    if (!(options.mac && options.signature) || (options.mac && options.signature)) {
      throw new EitherSignatureOrMacMustBeProvidedError()
    }

    const useSignature = !!options.signature
    const signingKey = useSignature ? options.mac.signingKey : options.signature.signingKey

    const documents = await Promise.all(
      options.inputDescriptorsOrRequests.map(async (idOrRequest) => {
        const document = findMdocMatchingDocType(
          options.documents,
          'id' in idOrRequest ? idOrRequest.id : idOrRequest.itemsRequest.docType
        )
        const deviceNamespaces = limitDisclosureCb(
          document.issuerSigned,
          idOrRequest as unknown as InputDescriptor & DocRequest
        )

        const deviceAuthenticationBytes = new DeviceAuthentication({
          sessionTranscript: options.sessionTranscript,
          docType: document.docType,
          deviceNamespaces: document.deviceSigned.deviceNamespaces,
        }).encode({ asDataItem: true })

        const unprotectedHeaders = signingKey.keyId
          ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyId, signingKey.keyId]]) })
          : new UnprotectedHeaders({})

        const protectedHeaders = new ProtectedHeaders({
          protectedHeaders: new Map([[Header.Algorithm, signingKey.algorithm]]),
        })

        if (!signingKey.algorithm) {
          throw new CoseInvalidAlgorithmError('Algorithm not defined on key, but is required for signing')
        }

        const deviceAuthOptions: DeviceAuthOptions = {}
        if (useSignature) {
          const deviceSignature = new DeviceSignature({
            unprotectedHeaders,
            protectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          await deviceSignature.addSignature({ signingKey }, context)

          deviceAuthOptions.deviceSignature = deviceSignature
        } else {
          const deviceMac = new DeviceMac({
            protectedHeaders,
            unprotectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          await deviceMac.addTag(
            {
              privateKey: signingKey,
              ephemeralKey: (options.mac as Required<typeof options.mac>).ephemeralKey,
              sessionTranscript: options.sessionTranscript,
            },
            context
          )

          deviceAuthOptions.deviceMac = deviceMac
        }

        return new Document({
          docType: document.docType,
          issuerSigned: document.issuerSigned,
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
    context: { crypto: MdocContext['crypto']; cose: MdocContext['cose'] }
  ) {
    return await DeviceResponse.create(
      limitDisclosureToDeviceRequestNameSpaces,
      { inputDescriptorsOrRequests: options.deviceRequest.docRequests, ...options },
      context
    )
  }

  public static async createWithPresentationDefinition(
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
    context: { crypto: MdocContext['crypto']; cose: MdocContext['cose'] }
  ) {
    return await DeviceResponse.create(
      limitDisclosureToInputDescriptor,
      { inputDescriptorsOrRequests: options.presentationDefinition.input_descriptors, ...options },
      context
    )
  }
}
