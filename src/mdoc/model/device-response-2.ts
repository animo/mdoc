import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { CborDecodeError } from '../../cbor/error'
import { Document, type DocumentStructure } from './document-2'
import type { DocumentError } from './mdoc'

export type DeviceResponseStructure = {
  version: string
  documents?: Array<DocumentStructure>
  documentErrors?: Array<DocumentError>
  status: number
}

export type DeviceResponseOptions = {
  version: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status: number
}

export class DeviceResponse2 extends CborStructure {
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
      structure.documentErrors = this.documentErrors
    }

    structure.status = this.status

    return structure as DeviceResponseStructure
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    const map = cborDecode<Map<string, unknown>>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    const documents = map.get('documents') as undefined | Array<Map<string, unknown>>

    if (documents && !Array.isArray(documents)) {
      throw new CborDecodeError('Document is found on device response, but not an array')
    }

    const decodedDocuments = documents?.map(Document.fromEncodedStructure)

    return new DeviceResponse2({
      version: map.get('version') as string,
      documents: decodedDocuments,
      documentErrors: map.get('documentErrors') as undefined,
      status: map.get('status') as number,
    })
  }
}
