import { addExtension } from 'cbor-x'

// tdate data item shall contain a date-time string as specified in RFC 3339 (with no fraction of seconds)
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: Date,
  tag: 0,
  encode: (date: Date, encode) => encode(`${date.toISOString().split('.')[0]}Z`),
  decode: (isoStringDateTime: string) => new Date(isoStringDateTime),
})
