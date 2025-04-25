import { CborStructure } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DocType } from './doctype'
import type { IntentToRetain } from './itent-to-retain'
import type { Namespace } from './namespace'

export type ItemsRequestStructure = {
  docType: DocType
  nameSpaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
}

export type ItemsRequestOptions = {
  docType: DocType
  nameSpaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
}

export class ItemsRequest extends CborStructure {
  public docType: DocType
  public nameSpaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>

  public constructor(options: ItemsRequestOptions) {
    super()
    this.docType = options.docType
    this.nameSpaces = options.nameSpaces
  }

  public encodedStructure(): ItemsRequestStructure {
    return {
      docType: this.docType,
      nameSpaces: this.nameSpaces,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: ItemsRequestStructure | Map<unknown, unknown>
  ): ItemsRequest {
    let structure = encodedStructure as ItemsRequestStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as ItemsRequestStructure
    }

    return new ItemsRequest({
      docType: structure.docType,
      nameSpaces: structure.nameSpaces,
    })
  }
}
