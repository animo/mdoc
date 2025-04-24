import { CborStructure } from '../../cbor'

export class DocumentError extends CborStructure {
  public encodedStructure(): unknown {
    throw new Error('Method not implemented.')
  }
}
