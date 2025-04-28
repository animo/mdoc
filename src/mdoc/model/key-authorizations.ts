import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { Namespace } from './namespace'

export type KeyAuthorizationsStructure = {
  nameSpaces?: Array<Namespace>
  dataElements?: Map<Namespace, Array<DataElementIdentifier>>
}

export type KeyAuthorizationsOptions = {
  namespaces?: Array<Namespace>
  dataElements?: Map<Namespace, Array<DataElementIdentifier>>
}

export class KeyAuthorizations extends CborStructure {
  public namespaces?: Array<Namespace>
  public dataElements?: Map<Namespace, Array<DataElementIdentifier>>

  public constructor(options: KeyAuthorizationsOptions) {
    super()
    this.namespaces = options.namespaces
    this.dataElements = options.dataElements
  }

  public encodedStructure(): KeyAuthorizationsStructure {
    return {
      nameSpaces: this.namespaces,
      dataElements: this.dataElements,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: KeyAuthorizationsStructure | Map<string, unknown>
  ): KeyAuthorizations {
    let structure = encodedStructure as KeyAuthorizationsStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as KeyAuthorizationsStructure
    }

    return new KeyAuthorizations({
      namespaces: structure.nameSpaces,
      dataElements: structure.dataElements,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): KeyAuthorizations {
    const structure = cborDecode<KeyAuthorizationsStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return KeyAuthorizations.fromEncodedStructure(structure)
  }
}
