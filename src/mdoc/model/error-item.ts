import { CborStructure } from '../../cbor'

export class ErrorItem extends CborStructure {
  public encodedStructure(): unknown {
    throw new Error('Method not implemented.')
  }
}
