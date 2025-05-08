import { type CborDecodeOptions, CborStructure, DataItem, cborDecode } from '../../cbor'
import { ItemsRequest, type ItemsRequestStructure } from './items-request'
import { SessionTranscript, type SessionTranscriptStructure } from './session-transcript'

export type ReaderAuthenticationStructure = [string, SessionTranscriptStructure, DataItem<ItemsRequestStructure>]

export type ReaderAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  itemsRequest: ItemsRequest
}

export class ReaderAuthentication extends CborStructure {
  public sessionTranscript: SessionTranscript
  public itemsRequest: ItemsRequest

  public constructor(options: ReaderAuthenticationOptions) {
    super()
    this.sessionTranscript = options.sessionTranscript
    this.itemsRequest = options.itemsRequest
  }

  public encodedStructure(): ReaderAuthenticationStructure {
    return [
      'ReaderAuthentication',
      this.sessionTranscript.encodedStructure(),
      DataItem.fromData(this.itemsRequest.encodedStructure()),
    ]
  }

  public static override fromEncodedStructure(encodedStructure: ReaderAuthenticationStructure): ReaderAuthentication {
    return new ReaderAuthentication({
      sessionTranscript: SessionTranscript.fromEncodedStructure(encodedStructure[1]),
      itemsRequest: ItemsRequest.fromEncodedStructure(encodedStructure[2].data),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ReaderAuthentication {
    const structure = cborDecode<ReaderAuthenticationStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return ReaderAuthentication.fromEncodedStructure(structure)
  }
}
