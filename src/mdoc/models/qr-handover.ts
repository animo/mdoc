import { CborStructure } from '../../cbor'

export type QrHandoverStructure = null

export class QrHandover extends CborStructure {
  public encodedStructure(): QrHandoverStructure {
    return null
  }

  public static override fromEncodedStructure(_encodedStructure: QrHandoverStructure): QrHandover {
    return new QrHandover()
  }
}
