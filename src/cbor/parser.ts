import { Encoder, type Options } from 'cbor-x'
import { DataItem } from './data-item'

export type CborOptions = Options & {
  unwrapTopLevelDataItem?: boolean
}

const encoderDefaults: CborOptions = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  unwrapTopLevelDataItem: true,
  variableMapSize: true,
}

export const cborDecode = <T>(input: Uint8Array, options: CborOptions = encoderDefaults): T => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  const decoded = enc.decode(input)
  return params.unwrapTopLevelDataItem && typeof decoded === 'object' && decoded instanceof DataItem
    ? (decoded.data as T)
    : (decoded as T)
}

export const cborEncode = (obj: unknown, options: Options = encoderDefaults): Uint8Array => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)
  return Uint8Array.from(enc.encode(obj))
}
