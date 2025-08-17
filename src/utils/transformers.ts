import { Buffer } from 'buffer'

type EncodingTypes =
  | 'ascii'
  | 'utf8'
  | 'utf-8'
  | 'utf16le'
  | 'utf-16le'
  | 'ucs2'
  | 'ucs-2'
  | 'base64'
  | 'base64url'
  | 'latin1'
  | 'binary'
  | 'hex'

const transformer = (type: EncodingTypes) => ({
  decode: (s: string) => Uint8Array.from(Buffer.from(s, type)),
  encode: (b: Uint8Array) => Buffer.from(b).toString(type),
})

export const base64 = transformer('base64')
export const base64url = transformer('base64url')
export const hex = transformer('hex')

export const bytesToString = (b: Uint8Array) => Buffer.from(b).toString()
export const stringToBytes = (s: string) => Uint8Array.from(Buffer.from(s))

export const concatBytes = (byteArrays: Array<Uint8Array>) => Uint8Array.from(Buffer.concat(byteArrays))

export const compareBytes = (lhs: Uint8Array, rhs: Uint8Array) => {
  if (lhs === rhs) return true
  if (lhs.byteLength !== rhs.byteLength) return false
  return lhs.every((b, i) => b === rhs[i])
}

export const dateToSeconds = (date?: Date): number => Math.floor((date?.getTime() ?? Date.now()) / 1000)
