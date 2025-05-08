import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { DeviceSigned, type DeviceSignedStructure } from './device-signed'
import type { DocType } from './doctype'
import type { ErrorItems } from './error-items'
import { IssuerSigned, type IssuerSignedStructure } from './issuer-signed'
import type { Namespace } from './namespace'

export type DocumentStructure = {
  docType: DocType
  issuerSigned: IssuerSignedStructure
  deviceSigned: DeviceSignedStructure
  errors?: Map<Namespace, ErrorItems>
}

export type DocumentOptions = {
  docType: DocType
  issuerSigned: IssuerSigned
  deviceSigned: DeviceSigned
  errors?: Map<Namespace, ErrorItems>
}

export class Document extends CborStructure {
  public docType: DocType
  public issuerSigned: IssuerSigned
  public deviceSigned: DeviceSigned
  public errors?: Map<Namespace, ErrorItems>

  public constructor(options: DocumentOptions) {
    super()
    this.docType = options.docType
    this.issuerSigned = options.issuerSigned
    this.deviceSigned = options.deviceSigned
    this.errors = options.errors
  }

  public encodedStructure(): DocumentStructure {
    const structure: DocumentStructure = {
      docType: this.docType,
      issuerSigned: this.issuerSigned.encodedStructure(),
      deviceSigned: this.deviceSigned.encodedStructure(),
    }

    if (this.errors) {
      structure.errors = this.errors
    }

    return structure
  }

  public static override fromEncodedStructure(encodedStructure: DocumentStructure | Map<unknown, unknown>): Document {
    let structure = encodedStructure as DocumentStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DocumentStructure
    }

    return new Document({
      docType: structure.docType,
      issuerSigned: IssuerSigned.fromEncodedStructure(structure.issuerSigned),
      deviceSigned: DeviceSigned.fromEncodedStructure(structure.deviceSigned),
      errors: structure.errors,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Document {
    const structure = cborDecode<DocumentStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Document.fromEncodedStructure(structure)
  }

  public getIssuerNamespace(namespace: Namespace) {
    const issuerNamespaces = this.issuerSigned.issuerNamespaces?.issuerNamespaces

    if (!issuerNamespaces) {
      return undefined
    }

    return issuerNamespaces.get(namespace)
  }
}
