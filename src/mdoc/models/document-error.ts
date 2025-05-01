import { CborStructure } from '../../cbor'
import type { DocType } from './doctype'
import type { ErrorCodeOld } from './mdoc'

export type DocumentErrorStructure = Map<DocType, ErrorCodeOld>

export type DocumentErrorOptions = {
  documentError: Map<DocType, ErrorCodeOld>
}

export class DocumentError extends CborStructure {
  public documentError: Map<DocType, ErrorCodeOld>

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
