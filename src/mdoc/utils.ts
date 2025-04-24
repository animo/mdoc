import { DataItem } from '../cbor/data-item.js'
import { cborDecode, cborEncode } from '../cbor/index.js'
import { base64 } from '../utils/transformers.js'

/**
 *
 * @todo transform this into a class
 *
 */
export const calculateDeviceAutenticationBytes = (
  sessionTranscript: Uint8Array | unknown,
  docType: string,
  nameSpaces: Map<string, Map<string, unknown>>
): Uint8Array => {
  let decodedSessionTranscript: unknown
  if (sessionTranscript instanceof Uint8Array) {
    // assume is encoded in a DataItem
    decodedSessionTranscript = (cborDecode(sessionTranscript) as DataItem).data
  } else {
    decodedSessionTranscript = sessionTranscript
  }

  const encode = DataItem.fromData([
    'DeviceAuthentication',
    decodedSessionTranscript,
    docType,
    DataItem.fromData(nameSpaces),
  ])

  const result = cborEncode(encode)

  return result
}

export function fromPem(pem: string): Uint8Array {
  const strippedPem = pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, '')
  return base64.decode(strippedPem)
}
