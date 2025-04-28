import type { Options as CborXParserOptions } from './cbor-x'
import { DataItem } from './data-item'
import { cborDecode, cborEncode } from './parser'

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

  /**
   *
   * @todo this needs to return the class instance of the abstract class extender
   *
   */
  public static decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    return cborDecode(bytes, options)
  }

  public static fromEncodedStructure(_encodedStructure: unknown): CborStructure {
    throw new Error('fromEncodedStructure must be implemented')
  }
}
