import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import { base64url } from '../../utils'
import { IssuerAuth, type IssuerAuthStructure } from './issuer-auth'
import { IssuerNamespace, type IssuerNamespaceStructure } from './issuer-namespace'
import type { Namespace } from './namespace'

export type IssuerSignedStructure = {
  nameSpaces?: IssuerNamespaceStructure
  issuerAuth: IssuerAuthStructure
}

export type IssuerSignedOptions = {
  issuerNamespaces?: IssuerNamespace
  issuerAuth: IssuerAuth
}

export class IssuerSigned extends CborStructure {
  public issuerNamespaces?: IssuerNamespace
  public issuerAuth: IssuerAuth

  public constructor(options: IssuerSignedOptions) {
    super()
    this.issuerNamespaces = options.issuerNamespaces
    this.issuerAuth = options.issuerAuth
  }

  public getIssuerNamespace(namespace: Namespace) {
    if (!this.issuerNamespaces) return undefined
    return this.issuerNamespaces.issuerNamespaces.get(namespace)
  }

  public getPrettyClaims(namespace: Namespace) {
    if (!this.issuerNamespaces) return undefined
    const issuerSignedItems = this.issuerNamespaces.issuerNamespaces.get(namespace)
    if (!issuerSignedItems) return undefined

    return issuerSignedItems.reduce((prev, curr) => ({ ...prev, [curr.elementIdentifier]: curr.elementValue }), {})
  }

  public get encodedForOid4Vci() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vci(encoded: string): IssuerSigned {
    return IssuerSigned.decode(base64url.decode(encoded))
  }

  public encodedStructure(): IssuerSignedStructure {
    const structure: Partial<IssuerSignedStructure> = {}

    if (this.issuerNamespaces) {
      structure.nameSpaces = this.issuerNamespaces.encodedStructure()
    }

    structure.issuerAuth = this.issuerAuth.encodedStructure()

    return structure as IssuerSignedStructure
  }

  public static override fromEncodedStructure(
    encodedStructure: IssuerSignedStructure | Map<string, unknown>
  ): IssuerSigned {
    let structure = encodedStructure as IssuerSignedStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as IssuerSignedStructure
    }

    return new IssuerSigned({
      issuerNamespaces: structure.nameSpaces ? IssuerNamespace.fromEncodedStructure(structure.nameSpaces) : undefined,
      issuerAuth: IssuerAuth.fromEncodedStructure(structure.issuerAuth),
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): IssuerSigned {
    const structure = cborDecode<IssuerSignedStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return IssuerSigned.fromEncodedStructure(structure)
  }
}
