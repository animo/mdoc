import { z } from 'zod'
import { DataItem } from './data-item'
import { cborDecode, cborEncode } from './parser'

export type CborEncodeOptions = {
  asDataItem?: boolean
}

// biome-ignore lint/suspicious/noExplicitAny: no explanation
export type EncodedStructureType<T> = T extends CborStructure<infer EncodedStructure, unknown> ? EncodedStructure : any
// biome-ignore lint/suspicious/noExplicitAny: no explanation
export type DecodedStructureType<T> = T extends CborStructure<unknown, infer DecodedStructure> ? DecodedStructure : any

export class CborStructure<EncodedStructure = unknown, DecodedStructure = EncodedStructure> {
  protected structure: DecodedStructure

  public constructor(structure: DecodedStructure) {
    this.structure = structure
  }

  public get decodedStructure(): DecodedStructure {
    return this.structure
  }

  /**
   * Static getter for the Zod codec schema that defines the CBOR structure.
   * Subclasses CAN override this to provide their specific schema for automatic encoding/decoding.
   * The schema should be a Zod schema or codec that handles validation and transformation.
   * If not provided, subclasses must override encode(), decode(), and fromEncodedStructure().
   */
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static get encodingSchema(): z.ZodType<any, any, any> | undefined {
    return undefined
  }

  /**
   * Returns the encoded structure that will be serialized to CBOR.
   * By default, returns the protected structure property.
   * Override if custom encoding logic is needed.
   */
  public get encodedStructure(): EncodedStructure {
    const encodingSchema = (this.constructor as typeof CborStructure).encodingSchema
    if (!encodingSchema) {
      throw new Error('encodedStructure must be implemented when encodingSchema is not provided')
    }

    return encodingSchema.encode(this.structure) as EncodedStructure
  }

  /**
   * Encodes this structure to CBOR bytes.
   */
  public encode(options?: CborEncodeOptions): Uint8Array {
    const encodedStructure = options?.asDataItem ? DataItem.fromData(this.encodedStructure) : this.encodedStructure

    return cborEncode(encodedStructure)
  }

  /**
   * Decodes CBOR bytes into a structure instance.
   * Uses the encodingSchema's decode() method to validate and transform the decoded data.
   */
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static decode<T extends CborStructure<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      encodingSchema: z.ZodType<any, any, any> | undefined
      fromEncodedStructure: (encodedStructure: EncodedStructureType<T>) => { decodedStructure: DecodedStructureType<T> }
    },
    bytes: Uint8Array
  ): T {
    const rawStructure = cborDecode(bytes)

    // May feel weird, but using new this makes TypeScript understand we may return a subclass
    return new this(this.fromEncodedStructure(rawStructure as EncodedStructureType<T>).decodedStructure)
  }

  /**
   * Creates a structure instance from the encoded CBOR structure (after calling cborDecode).
   *
   * Uses the encodingSchema's decode() method to validate and transform the structure if available.
   * Otherwise, subclasses must override this method.
   */
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static fromEncodedStructure<T extends CborStructure<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      encodingSchema: z.ZodType<any, any, any> | undefined
    },
    encodedStructure: EncodedStructureType<T>
  ): T {
    if (!this.encodingSchema) {
      throw new Error('fromEncodedStructure must be implemented when encodingSchema is not provided')
    }

    return new this(this.encodingSchema.decode(encodedStructure))
  }

  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static fromDataItem<T extends CborStructure<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      encodingSchema: z.ZodType<any, any, any> | undefined
      fromEncodedStructure: (encodedStructure: EncodedStructureType<T>) => { decodedStructure: DecodedStructureType<T> }
    },
    dataItem: unknown
  ): T {
    return new this(
      z
        .instanceof(DataItem)
        .transform((di) => di.data)
        // biome-ignore lint/suspicious/noExplicitAny: no explanation
        .transform((d) => this.fromEncodedStructure(d as any).decodedStructure)
        .parse(dataItem)
    )
  }

  /**
   * Creates a structure instance from the decoded structure.
   *
   * Uses the encodingSchema's parse method to validate the structure if available.
   * Otherwise, subclasses must override this method.
   */
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static fromDecodedStructure<T extends CborStructure<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      encodingSchema: z.ZodType<any, any, any> | undefined
    },
    decodedStructure: DecodedStructureType<T>
  ): T {
    const encodingSchema = (this.constructor as typeof CborStructure).encodingSchema
    if (!encodingSchema) {
      throw new Error('fromDecodedStructure must be implemented when encodingSchema is not provided')
    }

    // We the schema is a coded, we need to validate it against the output schema, not the input schema
    const decodedSchema = encodingSchema instanceof z.ZodPipe ? encodingSchema.out : encodingSchema

    return new this(z.parse(decodedSchema, decodedStructure))
  }
}
