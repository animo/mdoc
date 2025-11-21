import { Handover } from './handover'

export type QrHandoverStructure = null

export class QrHandover extends Handover {
  public encodedStructure(): QrHandoverStructure {
    return null
  }

  public static override fromEncodedStructure(_encodedStructure: QrHandoverStructure): QrHandover {
    return new QrHandover()
  }

  public static isCorrectHandover(structure: unknown): structure is QrHandoverStructure {
    return structure === null
  }
}
