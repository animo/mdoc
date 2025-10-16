import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

export type ValidityInfoStructure = {
  signed: Date
  validFrom: Date
  validUntil: Date
  expectedUpdate?: Date
}

export type ValidityInfoOptions = {
  signed: Date
  validFrom: Date
  validUntil: Date
  expectedUpdate?: Date
}

export class ValidityInfo extends CborStructure {
  public signed: Date
  public validFrom: Date
  public validUntil: Date
  public expectedUpdate?: Date

  public constructor(options: ValidityInfoStructure) {
    super()
    this.signed = options.signed
    this.validFrom = options.validFrom
    this.validUntil = options.validUntil
    this.expectedUpdate = options.expectedUpdate
  }

  public verifySigned(notBefore: Date, notAfter: Date): boolean {
    const isWithinRange = this.signed < notBefore || this.signed > notAfter
    return isWithinRange
  }

  public verifyValidUntil(now: Date = new Date()): boolean {
    return this.validUntil < now
  }

  public verifyValidFrom(now: Date = new Date()): boolean {
    return this.validFrom < now
  }

  public encodedStructure(): ValidityInfoStructure {
    const structure: ValidityInfoStructure = {
      signed: this.signed,
      validFrom: this.validFrom,
      validUntil: this.validUntil,
    }

    if (this.expectedUpdate) {
      structure.expectedUpdate = this.expectedUpdate
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: ValidityInfoStructure | Map<string, unknown>
  ): ValidityInfo {
    let structure = encodedStructure as ValidityInfoStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as ValidityInfoStructure
    }

    return new ValidityInfo(structure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ValidityInfo {
    const structure = cborDecode<ValidityInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    return ValidityInfo.fromEncodedStructure(structure)
  }
}
