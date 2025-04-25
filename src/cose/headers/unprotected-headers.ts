import { type CborDecodeOptions, CborStructure } from '../../cbor/cbor-structure.js'
import { cborDecode } from '../../cbor/parser.js'
import type { Header } from './defaults.js'

export type UnprotectedHeadersStructure = Map<Header | unknown, unknown>

export type UnprotectedHeadersOptions = {
  unprotectedHeaders?: Map<Header | unknown, unknown>
}

export class UnprotectedHeaders extends CborStructure {
  public headers?: Map<Header | unknown, unknown>

  public constructor(options: UnprotectedHeadersOptions) {
    super()
    this.headers = options.unprotectedHeaders
  }

  public encodedStructure(): UnprotectedHeadersStructure {
    return this.headers ?? new Map()
  }

  public static override fromEncodedStructure(encodedStructure: UnprotectedHeadersStructure): UnprotectedHeaders {
    return new UnprotectedHeaders({ unprotectedHeaders: encodedStructure })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): UnprotectedHeaders {
    const map = cborDecode<UnprotectedHeadersStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return UnprotectedHeaders.fromEncodedStructure(map)
  }
}
