import type { Options } from './cbor-x/index.js'

import { Encoder, addExtension } from './cbor-x/encode.js'

export { DataItem } from './data-item.js'

export { addExtension } from './cbor-x/index.js'

const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom')
export class DateOnly {
  private date: Date

  public constructor(date?: string) {
    this.date = date ? new Date(date) : new Date()
  }

  get [Symbol.toStringTag]() {
    return DateOnly.name
  }

  toISOString(): string {
    return this.date.toISOString().split('T')[0]
  }

  [customInspectSymbol](): string {
    return this.toISOString()
  }
}

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
}

// tdate data item shall contain a date-time string as specified in RFC 3339 (with no fraction of seconds)
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: Date,
  tag: 0,
  encode: (date: Date, encode) => encode(`${date.toISOString().split('.')[0]}Z`),
  decode: (isoStringDateTime: string) => new Date(isoStringDateTime),
})

// full-date data item shall contain a full-date string as specified in RFC 3339
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: DateOnly,
  tag: 1004,
  encode: (date: DateOnly, encode) => encode(date.toISOString()),
  decode: (isoStringDate: string) => new DateOnly(isoStringDate),
})

export const cborDecode = (
  input: Uint8Array,
  options: Options = encoderDefaults
  // biome-ignore lint/suspicious/noExplicitAny:
): any => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return enc.decode(input)
}

export const cborDecodeUnknown = (input: Uint8Array, options: Options = encoderDefaults): unknown => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return enc.decode(input)
}

export const cborEncode = (obj: unknown, options: Options = encoderDefaults): Uint8Array => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return enc.encode(obj)
}
