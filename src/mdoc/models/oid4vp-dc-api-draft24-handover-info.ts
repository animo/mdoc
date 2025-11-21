import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type Oid4vpDcApiDraft24HandoverInfoStructure = [string, string, string]

export type Oid4vpDcApiDraft24HandoverInfoOptions = {
  origin: string
  clientId: string
  nonce: string
}

export class Oid4vpDcApiDraft24HandoverInfo extends CborStructure {
  public origin: string
  public clientId: string
  public nonce: string

  public constructor(options: Oid4vpDcApiDraft24HandoverInfoOptions) {
    super()
    this.origin = options.origin
    this.clientId = options.clientId
    this.nonce = options.nonce
  }

  public encodedStructure(): Oid4vpDcApiDraft24HandoverInfoStructure {
    return [this.origin, this.clientId, this.nonce]
  }

  public static override fromEncodedStructure(
    encodedStructure: Oid4vpDcApiDraft24HandoverInfoStructure
  ): Oid4vpDcApiDraft24HandoverInfo {
    return new Oid4vpDcApiDraft24HandoverInfo({
      origin: encodedStructure[0],
      clientId: encodedStructure[1],
      nonce: encodedStructure[2],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpDcApiDraft24HandoverInfo {
    const structure = cborDecode<Oid4vpDcApiDraft24HandoverInfoStructure>(bytes, {
      ...(options ?? {}),
      mapsAsObjects: false,
    })
    return Oid4vpDcApiDraft24HandoverInfo.fromEncodedStructure(structure)
  }
}
