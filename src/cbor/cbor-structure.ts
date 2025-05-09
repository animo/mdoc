import type { Options as CborXParserOptions } from './cbor-x'
import { DataItem } from './data-item'
import { cborEncode } from './parser'

export type CborEncodeOptions = {
  asDataItem?: boolean
}

export type CborDecodeOptions = CborXParserOptions

export abstract class CborStructure {
  public abstract encodedStructure(): unknown

  public encode(options?: CborEncodeOptions): Uint8Array {
    let structure = this.encodedStructure()

    if (options?.asDataItem) {
      structure = DataItem.fromData(structure)
    }

    return cborEncode(structure)
  }

  public static decode(_bytes: Uint8Array, _options?: CborDecodeOptions): CborStructure {
    throw new Error('decode must be implemented')
  }

  public static fromEncodedStructure(_encodedStructure: unknown): CborStructure {
    throw new Error('fromEncodedStructure must be implemented')
  }
}
