import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import {
  CoseEphemeralMacKeyIsRequiredError,
  CoseInvalidAlgorithmError,
  type CoseKey,
  Header,
  ProtectedHeaders,
  UnprotectedHeaders,
} from '../../cose'
import { PresentationDefinitionOrDocRequestsAreRequiredError } from '../errors'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import type { DeviceNamespaces } from './device-namespaces'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import { DocRequest } from './doc-request'
import { Document, type DocumentStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import {
  findMdocMatchingDocType,
  limitDisclosureToDeviceRequestNameSpaces,
  limitDisclosureToInputDescriptor,
} from './pex-limit-disclosure'
import type { InputDescriptor, PresentationDefinition } from './presentation-definition'
import type { SessionTranscript } from './session-transcript'

export type DeviceResponseStructure = {
  version: string
  documents?: Array<DocumentStructure>
  documentErrors?: Array<DocumentErrorStructure>
  status: number
}

export type DeviceResponseOptions = {
  version: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status: number
}

export class DeviceResponse extends CborStructure {
  public version: string
  public documents?: Array<Document>
  public documentErrors?: Array<DocumentError>
  public status: number

  public constructor(options: DeviceResponseOptions) {
    super()
    this.version = options.version
    this.documents = options.documents
    this.documentErrors = options.documentErrors
    this.status = options.status
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

  public async sign(
    options: {
      presentationDefinition?: PresentationDefinition
      docRequests?: Array<DocRequest>
      sessionTranscript: SessionTranscript
      useSignature: boolean
      signingKey: CoseKey
      ephemeralMacKey?: CoseKey
    },
    context: { crypto: MdocContext['crypto']; cose: MdocContext['cose'] }
  ) {
    const requests = options.presentationDefinition?.input_descriptors ?? options.docRequests

    if (!requests) {
      throw new PresentationDefinitionOrDocRequestsAreRequiredError()
    }

    const isDeviceRequest = (request: InputDescriptor | DocRequest) => request instanceof DocRequest

    await Promise.all(
      requests.map(async (request) => {
        let document: Document
        let deviceNamespaces: DeviceNamespaces

        if (isDeviceRequest(request)) {
          const { docType } = request.itemsRequest
          document = findMdocMatchingDocType(this, docType)
          deviceNamespaces = limitDisclosureToDeviceRequestNameSpaces(document, request.itemsRequest.namespaces)
        } else {
          document = findMdocMatchingDocType(this, request.id)
          deviceNamespaces = limitDisclosureToInputDescriptor(document, request)
        }

        const deviceAuthenticationBytes = new DeviceAuthentication({
          sessionTranscript: options.sessionTranscript,
          docType: document.docType,
          deviceNamespaces: document.deviceSigned.deviceNamespaces,
        }).encode({ asDataItem: true })

        const unprotectedHeaders = options.signingKey.keyId
          ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyId, options.signingKey.keyId]]) })
          : new UnprotectedHeaders({})

        const protectedHeaders = new ProtectedHeaders({
          protectedHeaders: new Map([[Header.Algorithm, options.signingKey.algorithm]]),
        })

        if (!options.signingKey.algorithm) {
          throw new CoseInvalidAlgorithmError('Algorithm not defined on key, but is required for signing')
        }

        const deviceAuthOptions: DeviceAuthOptions = {}
        if (options.useSignature) {
          const deviceSignature = new DeviceSignature({
            unprotectedHeaders,
            protectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          await deviceSignature.addSignature({ key: options.signingKey }, context)

          deviceAuthOptions.deviceSignature = deviceSignature
        } else {
          if (!options.ephemeralMacKey) {
            throw new CoseEphemeralMacKeyIsRequiredError()
          }

          const deviceMac = new DeviceMac({
            protectedHeaders,
            unprotectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          })

          await deviceMac.addTag(
            {
              privateKey: options.signingKey,
              ephemeralKey: options.ephemeralMacKey,
              sessionTranscript: options.sessionTranscript,
            },
            context
          )

          deviceAuthOptions.deviceMac = deviceMac
        }

        document.deviceSigned = new DeviceSigned({
          deviceNamespaces,
          deviceAuth: new DeviceAuth(deviceAuthOptions),
        })
      })
    )
  }
}
