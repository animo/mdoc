import { type CborDecodeOptions, CborStructure, DataItem, cborDecode } from '../../cbor'
import { ItemsRequest, type ItemsRequestStructure } from './items-request'
import { ReaderAuth, type ReaderAuthStructure } from './reader-auth'

export type DocRequestStructure = {
  itemsRequest: DataItem<ItemsRequestStructure>
  readerAuth?: ReaderAuthStructure
}

export type DocRequestOptions = {
  itemsRequest: ItemsRequest
  readerAuth?: ReaderAuth
}

export class DocRequest extends CborStructure {
  public itemsRequest: ItemsRequest
  public readerAuth?: ReaderAuth

  public constructor(options: DocRequestOptions) {
    super()
    this.itemsRequest = options.itemsRequest
    this.readerAuth = options.readerAuth
  }

  public encodedStructure(): DocRequestStructure {
    const structure: DocRequestStructure = {
      itemsRequest: DataItem.fromData(this.itemsRequest.encodedStructure()),
    }

    if (this.readerAuth) {
      structure.readerAuth = this.readerAuth.encodedStructure()
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: DocRequestStructure | Map<unknown, unknown>
  ): DocRequest {
    let structure = encodedStructure as DocRequestStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DocRequestStructure
    }

    return new DocRequest({
      itemsRequest: ItemsRequest.fromEncodedStructure(structure.itemsRequest.data),
      readerAuth: structure.readerAuth ? ReaderAuth.fromEncodedStructure(structure.readerAuth) : undefined,
    })
  }

  public static decode(bytes: Uint8Array, options?: CborDecodeOptions): DocRequest {
    const map = cborDecode<Map<unknown, unknown>>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return DocRequest.fromEncodedStructure(map)
  }
}
