import { CborStructure } from '../../cbor/cbor-structure.js'

export type UnprotectedHeaderOptions = {
  unprotectedHeaders?: Map<unknown, unknown>
}

export class UnprotectedHeaders extends CborStructure {
  public headers?: Map<unknown, unknown>

  public constructor(options: UnprotectedHeaderOptions) {
    super()
    this.headers = options.unprotectedHeaders
  }

  public encodedStructure(): unknown {
    return this.headers ?? new Map()
  }
}
