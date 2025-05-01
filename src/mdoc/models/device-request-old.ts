import { cborDecode, cborEncode } from '../../cbor'
import type { ItemsRequestData } from '../items-request'
import { ItemsRequestOld } from '../items-request'

export interface DocRequestOld {
  itemsRequest: ItemsRequestOld
  readerAuth?: ReaderAuthOld
}

export type ReaderAuthOld = [
  Uint8Array | undefined,
  Uint8Array | undefined,
  Uint8Array | undefined,
  Uint8Array | undefined,
]

export type DeviceRequestNameSpaces = Map<string, Map<string, boolean>>

export class DeviceRequestOld {
  constructor(
    public version: string,
    public docRequests: DocRequestOld[]
  ) {}

  public static from(
    version: string,
    docRequests: {
      itemsRequestData: ItemsRequestData
      readerAuth?: ReaderAuthOld
    }[]
  ) {
    return new DeviceRequestOld(
      version,
      docRequests.map((docRequest) => {
        return {
          ...docRequest,
          itemsRequest: ItemsRequestOld.create(
            docRequest.itemsRequestData.docType,
            docRequest.itemsRequestData.nameSpaces,
            docRequest.itemsRequestData.requestInfo
          ),
        }
      })
    )
  }

  public static parse(cbor: Uint8Array) {
    const res = cborDecode(cbor, {
      tagUint8Array: false,
      useRecords: true,
      mapsAsObjects: true,
      // biome-ignore lint/suspicious/noExplicitAny:
    }) as { version: string; docRequests: any[] }

    const { version, docRequests } = res

    const parsedDocRequests: DocRequestOld[] = docRequests.map((docRequest) => {
      const itemsRequest = new ItemsRequestOld(docRequest.itemsRequest)

      return {
        ...docRequest,
        itemsRequest,
      }
    })

    return new DeviceRequestOld(version, parsedDocRequests)
  }

  public static encodeDocRequest(r: DocRequestOld) {
    // biome-ignore lint/suspicious/noExplicitAny:
    return new Map<string, any>([
      ['itemsRequest', r.itemsRequest.dataItem],
      ['readerAuth', r.readerAuth],
    ])
  }

  encode() {
    return cborEncode({
      version: this.version,
      docRequests: this.docRequests.map(DeviceRequestOld.encodeDocRequest),
    })
  }
}
