import { CborStructure } from '../../cbor'

// TODO
type CoseKey = Map<unknown, unknown>

export type EReaderKeyStructure = CoseKey

export type EReaderKeyOptions = {
  coseKey: CoseKey
}

export class EReaderKey extends CborStructure {
  public coseKey: CoseKey

  public constructor(options: EReaderKeyOptions) {
    super()
    this.coseKey = options.coseKey
  }

  public encodedStructure(): EReaderKeyStructure {
    return this.coseKey
  }

  public static override fromEncodedStructure(encodedStructure: EReaderKeyStructure): EReaderKey {
    return new EReaderKey({ coseKey: encodedStructure })
  }
}
