import z from 'zod'
import { addExtension } from './cbor-x'
import { cborDecode, cborEncode } from './parser'

export const zDataItemCodec = (outputSchema: z.ZodType) =>
  z.codec(z.instanceof(DataItem), outputSchema, {
    encode: (data) => DataItem.fromData(data),
    decode: (dataItem) => dataItem.data,
  })

export type DataItemOptions<T = unknown> =
  | {
      data: T
      buffer: Uint8Array
    }
  | { data: T }
  | { buffer: Uint8Array }

/**
 * DataItem is an extension defined https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
 *  > Sometimes it is beneficial to carry an embedded CBOR data item that is
 *  > not meant to be decoded immediately at the time the enclosing data item is being decoded.
 *
 * The idea of this class is to provide lazy encode and decode of cbor data.
 *
 * Due to a bug in the cbor-x library, we are eagerly encoding the data in the constructor.
 * https://github.com/kriszyp/cbor-x/issues/83
 *
 */
export class DataItem<T = unknown> {
  #data?: T
  #buffer: Uint8Array

  public constructor(options: DataItemOptions<T>) {
    if (!('data' in options) && !('buffer' in options)) {
      throw new Error('DataItem must be initialized with either the data or a buffer')
    }

    if ('data' in options) this.#data = options.data
    this.#buffer = 'buffer' in options ? options.buffer : cborEncode(options.data)
  }

  public get data(): T {
    if (!this.#data) {
      this.#data = cborDecode(this.#buffer) as T
    }
    return this.#data
  }

  public get buffer(): Uint8Array {
    return this.#buffer
  }

  public static fromData<T>(data: T): DataItem<T> {
    return new DataItem({ data })
  }

  public static fromBuffer<T>(buffer: Uint8Array): DataItem<T> {
    return new DataItem({ buffer })
  }
}

addExtension({
  Class: DataItem,
  tag: 24,
  encode: (instance: DataItem<unknown>, encode) => {
    return encode(instance.buffer)
  },
  decode: (buffer: Uint8Array): object => {
    return DataItem.fromBuffer(buffer)
  },
})
