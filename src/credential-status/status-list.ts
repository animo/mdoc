import * as zlib from 'node:zlib'
import { cborDecode, cborEncode } from '../cbor'
import { type AllowedBitsPerEntry, StatusArray, allowedBitsPerEntry } from './status-array'

export interface CborStatusListOptions {
  statusArray: StatusArray
  aggregationUri?: string
}

export class StatusList {
  static buildCborStatusList(options: CborStatusListOptions): Uint8Array {
    const compressed = options.statusArray.compress()

    const statusList: Record<string, number | Uint8Array | string> = {
      bits: options.statusArray.getBitsPerEntry(),
      lst: compressed,
    }

    if (options.aggregationUri) {
      statusList.aggregation_uri = options.aggregationUri
    }
    return cborEncode(statusList)
  }

  static verifyStatus(cborStatusList: Uint8Array, index: number, expectedStatus: number): boolean {
    const statusList = cborDecode(cborStatusList) as Map<string, Uint8Array | number | string>
    const bits = statusList.get('bits') as AllowedBitsPerEntry
    const lst = statusList.get('lst') as Uint8Array

    if (!statusList || !lst || !bits) {
      throw new Error('Invalid status list format.')
    }
    if (!allowedBitsPerEntry.includes(bits)) {
      throw new Error(`Invalid bits per entry: ${bits}. Allowed values are ${allowedBitsPerEntry.join(', ')}.`)
    }

    const statusArray = new StatusArray(bits, zlib.inflateSync(lst))
    const actualStatus = statusArray.get(index)
    if (actualStatus !== expectedStatus) {
      return false
    }
    else {
      return true
    }
  }
}
