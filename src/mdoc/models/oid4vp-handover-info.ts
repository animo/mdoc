import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type Oid4vpHandoverInfoStructure = [string, string, Uint8Array | null, string]

export type Oid4vpHandoverInfoOptions = {
  clientId: string
  nonce: string
  jwkThumbprint?: Uint8Array
  responseUri: string
}

export class Oid4vpHandoverInfo extends CborStructure {
  public clientId: string
  public nonce: string
  public jwkThumbprint?: Uint8Array
  public responseUri: string

  public constructor(options: Oid4vpHandoverInfoOptions) {
    super()
    this.clientId = options.clientId
    this.nonce = options.nonce
    this.jwkThumbprint = options.jwkThumbprint
    this.responseUri = options.responseUri
  }

  public encodedStructure(): Oid4vpHandoverInfoStructure {
    return [this.clientId, this.nonce, this.jwkThumbprint ?? null, this.responseUri]
  }

  public static override fromEncodedStructure(encodedStructure: Oid4vpHandoverInfoStructure): Oid4vpHandoverInfo {
    return new Oid4vpHandoverInfo({
      clientId: encodedStructure[0],
      nonce: encodedStructure[1],
      jwkThumbprint: encodedStructure[2] ?? undefined,
      responseUri: encodedStructure[3],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpHandoverInfo {
    const structure = cborDecode<Oid4vpHandoverInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Oid4vpHandoverInfo.fromEncodedStructure(structure)
  }
}
