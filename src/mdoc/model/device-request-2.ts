import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { DocRequest, type DocRequestStructure } from './doc-request'

export type DeviceRequestStructure = {
  version: string
  docRequests: Array<DocRequestStructure>
}

export type DeviceRequestOptions = {
  version: string
  docRequests: Array<DocRequest>
}

export class DeviceRequest extends CborStructure {
  public version: string
  public docRequests: Array<DocRequest>

  public constructor(options: DeviceRequestOptions) {
    super()
    this.version = options.version
    this.docRequests = options.docRequests
  }

  public encodedStructure(): DeviceRequestStructure {
    return {
      version: this.version,
      docRequests: this.docRequests.map((dr) => dr.encodedStructure()),
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceRequestStructure | Map<unknown, unknown>
  ): DeviceRequest {
    let structure = encodedStructure as DeviceRequestStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as DeviceRequestStructure
    }

    return new DeviceRequest({
      version: structure.version,
      docRequests: structure.docRequests.map(DocRequest.fromEncodedStructure),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceRequest {
    const map = cborDecode<Map<unknown, unknown>>(bytes, options)
    return DeviceRequest.fromEncodedStructure(map)
  }
}
