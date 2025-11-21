import { CborStructure } from '../../cbor'

export abstract class Handover extends CborStructure {
  public static isCorrectHandover(_structure: unknown): boolean {
    return false
  }
}
