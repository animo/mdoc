import { cborEncode } from '../../cbor/index.js'
import type { IssuerSignedDocument } from './issuer-signed-document.js'

export type ErrorCodeOld = number
export type ErrorItemsOld = Record<string, ErrorCodeOld>
export interface DocumentErrorOld {
  DocType: ErrorCodeOld
}

export enum MDocStatusOld {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}

export class MDocOld {
  constructor(
    public readonly documents: IssuerSignedDocument[] = [],
    public readonly version = '1.0',
    public readonly status: MDocStatusOld = MDocStatusOld.OK,
    public readonly documentErrors: DocumentErrorOld[] = []
  ) {}

  addDocument(document: IssuerSignedDocument) {
    if (typeof document.issuerSigned === 'undefined') {
      throw new Error('Cannot add an unsigned document')
    }
    this.documents.push(document)
  }

  encode() {
    // TODO: ERROR MISSING
    return cborEncode({
      version: this.version,
      documents: this.documents.map((doc) => doc.prepare()),
      status: this.status,
    })
  }
}
