import { z } from 'zod'
import { CborStructure } from '../../cbor'

// Zod schema for DocumentError
const documentErrorSchema = z.map(z.string(), z.number())

export type DocumentErrorStructure = z.infer<typeof documentErrorSchema>

export type DocumentErrorOptions = {
  documentError: DocumentErrorStructure
}

export class DocumentError extends CborStructure<DocumentErrorStructure> {
  public static override encodingSchema = documentErrorSchema

  /**
   * Map where keys are namespaces and values are error codes
   */
  public get documentError() {
    return this.structure
  }

  public static create(options: DocumentErrorOptions): DocumentError {
    return new DocumentError(options.documentError)
  }
}
