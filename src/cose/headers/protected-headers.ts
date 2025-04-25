import { type CborDecodeOptions, CborStructure } from '../../cbor/cbor-structure.js'
import { cborDecode, cborEncode } from '../../cbor/parser.js'

export type ProtectedHeadersStructure = Uint8Array

export type ProtectedHeaderOptions = {
  protectedHeaders?: Map<unknown, unknown> | Uint8Array
}

export class ProtectedHeaders extends CborStructure {
  public headers?: Map<unknown, unknown>

  public constructor(options: ProtectedHeaderOptions) {
    super()

    if (options.protectedHeaders instanceof Map) {
      this.headers = options.protectedHeaders
    } else if (options.protectedHeaders instanceof Uint8Array) {
      this.headers = cborDecode<Map<unknown, unknown>>(options.protectedHeaders)
    }
  }

  public encodedStructure(): ProtectedHeadersStructure {
    return cborEncode(this.headers) ?? new Uint8Array()
  }

  public static override fromEncodedStructure(encodedStructure: ProtectedHeadersStructure): ProtectedHeaders {
    return new ProtectedHeaders({ protectedHeaders: encodedStructure })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ProtectedHeaders {
    const map = cborDecode<ProtectedHeadersStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return ProtectedHeaders.fromEncodedStructure(map)
  }
}
