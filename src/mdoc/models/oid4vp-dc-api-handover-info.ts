import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type Oid4vpDcApiHandoverInfoStructure = [string, string, Uint8Array | null]

export type Oid4vpDcApiHandoverInfoOptions = {
  origin: string
  nonce: string
  jwkThumbprint?: Uint8Array
}

export class Oid4vpDcApiHandoverInfo extends CborStructure {
  public origin: string
  public nonce: string
  public jwkThumbprint?: Uint8Array

  public constructor(options: Oid4vpDcApiHandoverInfoOptions) {
    super()
    this.origin = options.origin
    this.nonce = options.nonce
    this.jwkThumbprint = options.jwkThumbprint
  }

  public encodedStructure(): Oid4vpDcApiHandoverInfoStructure {
    return [this.origin, this.nonce, this.jwkThumbprint ?? null]
  }

  public static override fromEncodedStructure(
    encodedStructure: Oid4vpDcApiHandoverInfoStructure
  ): Oid4vpDcApiHandoverInfo {
    return new Oid4vpDcApiHandoverInfo({
      origin: encodedStructure[0],
      nonce: encodedStructure[1],
      jwkThumbprint: encodedStructure[2] ?? undefined,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpDcApiHandoverInfo {
    const structure = cborDecode<Oid4vpDcApiHandoverInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Oid4vpDcApiHandoverInfo.fromEncodedStructure(structure)
  }
}
