import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type SessionDataStructure = {
  status?: number
  data?: Uint8Array
}

export type SessionDataOptions = {
  status?: number
  data?: Uint8Array
}

export class SessionData extends CborStructure {
  public status?: number
  public data?: Uint8Array

  public constructor(options: SessionDataOptions) {
    super()
    this.status = options.status
    this.data = options.data
  }

  public encodedStructure(): SessionDataStructure {
    const structure: SessionDataStructure = {}

    if (this.status) structure.status = this.status
    if (this.data) structure.data = this.data

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: SessionDataStructure | Map<unknown, unknown>
  ): SessionData {
    let structure = encodedStructure as SessionDataStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as SessionDataStructure
    }

    return new SessionData({
      status: structure.status,
      data: structure.data,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): SessionData {
    const structure = cborDecode<SessionDataStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return SessionData.fromEncodedStructure(structure)
  }
}
