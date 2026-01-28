import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'

export const unprotectedHeadersStructure = z.map(z.number(), z.unknown())

export type UnprotectedHeadersStructure = z.infer<typeof unprotectedHeadersStructure>

export type UnprotectedHeaderOptions = {
  unprotectedHeaders?: UnprotectedHeadersStructure
}

export class UnprotectedHeaders extends CborStructure<UnprotectedHeadersStructure> {
  public static override get encodingSchema() {
    return unprotectedHeadersStructure
  }

  public get headers() {
    return this.structure
  }

  public static create(options: UnprotectedHeaderOptions) {
    return this.fromDecodedStructure(options.unprotectedHeaders ?? new Map())
  }
}
