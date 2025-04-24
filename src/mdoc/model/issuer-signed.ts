import { CborStructure } from '../../cbor'
import { IssuerAuth, type IssuerAuthStructure } from './issuer-auth'
import { IssuerNamespace, type IssuerNamespaceStructure } from './issuer-namespace'

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
      structure = {
        nameSpaces: encodedStructure.get('nameSpaces') as undefined | IssuerNamespaceStructure,
        issuerAuth: encodedStructure.get('issuerAuth') as IssuerAuthStructure,
      }
    }

    return new IssuerSigned({
      issuerNamespaces: structure.nameSpaces ? IssuerNamespace.fromEncodedStructure(structure.nameSpaces) : undefined,
      issuerAuth: IssuerAuth.fromEncodedStructure(structure.issuerAuth),
    })
  }
}
