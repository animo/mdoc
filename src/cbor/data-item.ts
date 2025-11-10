import { cborDecode, cborEncode } from '.'
import { addExtension } from './cbor-x'

export type DataItemParams<T = unknown> =
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

  constructor(params: DataItemParams<T>) {
    if (!('data' in params) && !('buffer' in params)) {
      throw new Error('DataItem must be initialized with either the data or a buffer')
    }

    if ('data' in params) this.#data = params.data
    this.#buffer = 'buffer' in params ? params.buffer : cborEncode(params.data)
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
}

addExtension({
  Class: DataItem,
  tag: 24,
  encode: (instance: DataItem<unknown>, encode) => {
    return encode(instance.buffer)
  },
  decode: (buffer: Uint8Array): object => {
    return new DataItem({ buffer })
  },
})
