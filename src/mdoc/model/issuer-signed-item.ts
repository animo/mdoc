import { CborStructure } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'

export type IssuerSignedItemStructure = {
  digestID: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export class IssuerSignedItem extends CborStructure {
  public digestId: number
  public random: Uint8Array
  public elementIdentifier: DataElementIdentifier
  public elementValue: DataElementValue

  public constructor(options: IssuerSignedItemOptions) {
    super()
    this.digestId = options.digestId
    this.random = options.random
    this.elementIdentifier = options.elementIdentifier
    this.elementValue = options.elementValue
  }

  public encodedStructure(): IssuerSignedItemStructure {
    return {
      digestID: this.digestId,
      random: this.random,
      elementIdentifier: this.elementIdentifier,
      elementValue: this.elementValue,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: IssuerSignedItemStructure | Map<string, unknown>
  ): IssuerSignedItem {
    let structure = encodedStructure as IssuerSignedItemStructure

    if (encodedStructure instanceof Map) {
      structure = {
        digestID: encodedStructure.get('digestID') as IssuerSignedItemStructure['digestID'],
        random: encodedStructure.get('random') as IssuerSignedItemStructure['random'],
        elementIdentifier: encodedStructure.get('elementIdentifier') as IssuerSignedItemStructure['elementIdentifier'],
        elementValue: encodedStructure.get('elementValue') as IssuerSignedItemStructure['elementValue'],
      }
    }

    return new IssuerSignedItem({
      digestId: structure.digestID,
      random: structure.random,
      elementIdentifier: structure.elementIdentifier,
      elementValue: structure.elementValue,
    })
  }
}
