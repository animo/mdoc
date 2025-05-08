import { CborStructure } from '../../cbor'
import type { DocType } from './doctype'
import type { ErrorCode } from './error-code'

export type DocumentErrorStructure = Map<DocType, ErrorCode>

export type DocumentErrorOptions = {
  documentError: Map<DocType, ErrorCode>
}

export class DocumentError extends CborStructure {
  public documentError: Map<DocType, ErrorCode>

  public constructor(options: DocumentErrorOptions) {
    super()
    this.documentError = options.documentError
  }

  public encodedStructure(): DocumentErrorStructure {
    return this.documentError
  }

  public static override fromEncodedStructure(encodedStructure: DocumentErrorStructure): DocumentError {
    return new DocumentError({ documentError: encodedStructure })
  }
}
