/**
 *
 * @todo Make all the properties also classes here, instead of just a byte array
 * If we just accept a byte array, we would have to check if it is encapsulated in a data item, or not
 *
 * @todo make specific session transcripts for webAPI, OID4VPDCApi, OID4VP
 */

import { DataItem, cborEncode } from '../../cbor'
import type { Handover } from './handover'

type SessionTranscriptOptions = {
  deviceEngagementBytes: Uint8Array | null
  eReaderKeyBytes: Uint8Array | null
  handover: Handover
}

export class SessionTranscript {
  public deviceEngagementBytes: Uint8Array | null
  public eReaderKeyBytes: Uint8Array | null
  public handover: Handover

  public constructor(options: SessionTranscriptOptions) {
    this.handover = options.handover
    this.eReaderKeyBytes = options.eReaderKeyBytes
    this.deviceEngagementBytes = options.deviceEngagementBytes
  }

  public get encode() {
    return cborEncode(DataItem.fromData([this.deviceEngagementBytes, this.eReaderKeyBytes, this.handover.encode()]))
  }
}
