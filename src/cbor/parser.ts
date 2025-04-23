import { Encoder, type Options } from './cbor-x'

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
}

export const cborDecode = <T>(input: Uint8Array, options: Options = encoderDefaults): T => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return enc.decode(input) as T
}

export const cborEncode = (obj: unknown, options: Options = encoderDefaults): Uint8Array => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return enc.encode(obj)
}
