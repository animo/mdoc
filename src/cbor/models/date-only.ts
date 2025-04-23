import { addExtension } from '../cbor-x'

const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom')
export class DateOnly {
  private date: Date

  public constructor(date?: string) {
    this.date = date ? new Date(date) : new Date()
  }

  get [Symbol.toStringTag]() {
    return DateOnly.name
  }

  toString() {
    return this.toISOString()
  }

  toJSON() {
    return this.toISOString()
  }

  toISOString(): string {
    return this.date.toISOString().split('T')[0]
  }

  [customInspectSymbol](): string {
    return this.toISOString()
  }
}

// full-date data item shall contain a full-date string as specified in RFC 3339
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: DateOnly,
  tag: 1004,
  encode: (date: DateOnly, encode) => encode(date.toISOString()),
  decode: (isoStringDate: string) => new DateOnly(isoStringDate),
})
