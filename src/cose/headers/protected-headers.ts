import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import { cborDecode, cborEncode } from '../../cbor/parser.js'
import { zUint8Array } from '../../utils/zod.js'

// TODO: typedMap with known keys (Header enum)

export const protectedHeadersEncodedStructure = zUint8Array
export const protectedHeadersDecodedStructure = z.map(z.number(), z.unknown())

export type ProtectedHeadersDecodedStructure = z.infer<typeof protectedHeadersDecodedStructure>
export type ProtectedHeadersEncodedStructure = z.infer<typeof protectedHeadersEncodedStructure>

export type ProtectedHeaderOptions = {
  protectedHeaders?: ProtectedHeadersDecodedStructure
}

export class ProtectedHeaders extends CborStructure<
  ProtectedHeadersEncodedStructure,
  ProtectedHeadersDecodedStructure
> {
  public static override encodingSchema = z.codec(protectedHeadersEncodedStructure, protectedHeadersDecodedStructure, {
    // TODO: Senders SHOULD encode a zero-length map as a zero-length string rather than as a zero-length map
    encode: (decoded) => cborEncode(decoded) as Uint8Array<ArrayBuffer>,
    decode: (encoded) => cborDecode(encoded),
  })

  public get headers() {
    return this.structure
  }

  public static create(options: ProtectedHeaderOptions) {
    return this.fromDecodedStructure(options.protectedHeaders ?? new Map())
  }
}
