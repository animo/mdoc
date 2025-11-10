import { CborStructure, DataItem } from '../../cbor'
import { IssuerSignedItem, type IssuerSignedItemStructure } from './issuer-signed-item'
import type { Namespace } from './namespace'

export type IssuerNamespaceStructure = Map<Namespace, Array<DataItem<IssuerSignedItemStructure>>>

export type IssuerNamespaceOptions = {
  issuerNamespaces: Map<Namespace, Array<IssuerSignedItem>>
}

export class IssuerNamespace extends CborStructure {
  public issuerNamespaces: Map<Namespace, Array<IssuerSignedItem>>

  public constructor(options: IssuerNamespaceOptions) {
    super()
    this.issuerNamespaces = options.issuerNamespaces
  }

  public encodedStructure(): IssuerNamespaceStructure {
    const map: IssuerNamespaceStructure = new Map()

    this.issuerNamespaces.forEach((v, k) => {
      const value = v.map((isi) => DataItem.fromData(isi.encodedStructure()))
      map.set(k, value)
    })

    return map
  }

  public static override fromEncodedStructure(encodedStructure: IssuerNamespaceStructure): IssuerNamespace {
    const issuerNamespaces = new Map()

    encodedStructure.forEach((v, k) => {
      issuerNamespaces.set(
        k,
        v.map((di) => IssuerSignedItem.fromEncodedStructure(di.data))
      )
    })

    return new IssuerNamespace({ issuerNamespaces })
  }

  public get(namespace: string) {
    return this.issuerNamespaces.get(namespace)
  }
}
