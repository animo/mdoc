import { DataItem } from '../cbor/data-item.js'
import { cborEncode } from '../cbor/index.js'
import { base64 } from '../utils/transformers.js'
import type { DeviceNamespaces } from './models/device-namespaces.js'
import type { DocType } from './models/doctype.js'
import type { SessionTranscript } from './models/session-transcript.js'

/**
 *
 * @todo transform this into a class
 *
 */
export const calculateDeviceAutenticationBytes = (
  sessionTranscript: SessionTranscript,
  docType: DocType,
  namespaces: DeviceNamespaces
): Uint8Array => {
  const encode = DataItem.fromData([
    'DeviceAuthentication',
    sessionTranscript.encode(),
    docType,
    DataItem.fromData(namespaces),
  ])

  return cborEncode(encode)
}

export function fromPem(pem: string): Uint8Array {
  const strippedPem = pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, '')
  return base64.decode(strippedPem)
}
