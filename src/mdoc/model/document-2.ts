import { CborStructure } from '../../cbor'
import { DeviceSigned, type DeviceSignedStructure } from './device-signed'
import type { DocType } from './doctype'
import type { ErrorItem } from './error-item'
import { IssuerSigned, type IssuerSignedStructure } from './issuer-signed'
import type { Namespace } from './namespace'

export type DocumentStructure = {
  docType: DocType
  issuerSigned: IssuerSignedStructure
  deviceSigned: DeviceSignedStructure
  errors?: Map<Namespace, ErrorItem>
}

export type DocumentOptions = {
  docType: DocType
  issuerSigned: IssuerSigned
  deviceSigned: DeviceSigned
  errors?: Map<Namespace, ErrorItem>
}

export class Document extends CborStructure {
  public docType: DocType
  public issuerSigned: IssuerSigned
  public deviceSigned: DeviceSigned
  public errors?: Map<Namespace, ErrorItem>

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

  public static override fromEncodedStructure(encodedStructure: DocumentStructure | Map<string, unknown>): Document {
    let structure = encodedStructure as DocumentStructure

    if (encodedStructure instanceof Map) {
      structure = {
        docType: encodedStructure.get('docType') as DocumentStructure['docType'],
        issuerSigned: encodedStructure.get('issuerSigned') as DocumentStructure['issuerSigned'],
        deviceSigned: encodedStructure.get('deviceSigned') as DocumentStructure['deviceSigned'],
        errors: encodedStructure.get('errors') as DocumentStructure['errors'],
      }
    }

    return new Document({
      docType: structure.docType,
      issuerSigned: IssuerSigned.fromEncodedStructure(structure.issuerSigned),
      deviceSigned: DeviceSigned.fromEncodedStructure(structure.deviceSigned),
      errors: structure.errors,
    })
  }
}
