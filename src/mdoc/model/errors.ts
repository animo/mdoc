import { CborStructure } from '../../cbor'
import { ErrorItems, type ErrorItemsStructure } from './error-items'
import type { Namespace } from './namespace'

export type ErrorsStructure = Map<Namespace, ErrorItemsStructure>

export type ErrorsOptions = {
  errors: Map<Namespace, ErrorItems>
}

export class Errors extends CborStructure {
  public errors: Map<Namespace, ErrorItems>

  public constructor(options: ErrorsOptions) {
    super()
    this.errors = options.errors
  }

  public encodedStructure(): ErrorsStructure {
    const map: ErrorsStructure = new Map()

    this.errors.forEach((v, k) => {
      map.set(k, v.encodedStructure())
    })

    return map
  }

  public static override fromEncodedStructure(encodedStructure: ErrorsStructure): Errors {
    const errors = new Map<Namespace, ErrorItems>()

    encodedStructure.forEach((v, k) => {
      errors.set(k, ErrorItems.fromEncodedStructure(v))
    })

    return new Errors({ errors })
  }
}
