import * as zlib from 'pako'
import { cborDecode, cborEncode } from '../cbor'
import { type AllowedBitsPerEntry, StatusArray, allowedBitsPerEntry } from './status-array'

export interface CborStatusListOptions {
  statusArray: StatusArray
  aggregationUri?: string
}

export interface CborStatusList {
  bits: AllowedBitsPerEntry
  lst: Uint8Array
  aggregation_uri?: string
}

export class StatusList {
  static buildCborStatusList(options: CborStatusListOptions): Uint8Array {
    const compressed = options.statusArray.compress()

    const statusList: CborStatusList = {
      bits: options.statusArray.bitsPerEntry,
      lst: compressed,
    }

    if (options.aggregationUri) {
      statusList.aggregation_uri = options.aggregationUri
    }
    return cborEncode(statusList)
  }

  static verifyStatus(cborStatusList: Uint8Array, index: number, expectedStatus: number): boolean {
    const decoded = cborDecode(cborStatusList)
    if (!(decoded instanceof Map)) {
      throw new Error('Decoded CBOR data is not a Map.')
    }

    const statusList: CborStatusList = {
      bits: decoded.get('bits') as AllowedBitsPerEntry,
      lst: decoded.get('lst') as Uint8Array,
      aggregation_uri: decoded.get('aggregation_uri') as string | undefined,
    }
    const { bits, lst } = statusList

    if (!statusList || !lst || !bits) {
      throw new Error('Invalid status list format.')
    }
    if (!allowedBitsPerEntry.includes(bits)) {
      throw new Error(`Invalid bits per entry: ${bits}. Allowed values are ${allowedBitsPerEntry.join(', ')}.`)
    }

    const statusArray = new StatusArray(bits, zlib.inflate(lst))
    const actualStatus = statusArray.get(index)
    return actualStatus === expectedStatus
  }
}
