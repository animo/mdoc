import { CborStructure } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { ErrorCode } from './error-code'

export type ErrorItemsStructure = Map<DataElementIdentifier, ErrorCode>

export type ErrorItemsOptions = {
  errorItems: Map<DataElementIdentifier, ErrorCode>
}

export class ErrorItems extends CborStructure {
  public errorItems: Map<DataElementIdentifier, ErrorCode>

  public constructor(options: ErrorItemsOptions) {
    super()
    this.errorItems = options.errorItems
  }

  public encodedStructure(): ErrorItemsStructure {
    return this.errorItems
  }

  public static fromEncodedStructure(encodedStructure: ErrorItemsStructure): ErrorItems {
    return new ErrorItems({ errorItems: encodedStructure })
  }
}
