import { CborStructure } from '../../cbor'
import { Oidc, type OidcStructure } from './oidc'
import { WebApi, type WebApiStructure } from './web-api'

export type ServerRetrievalMethodStructure = {
  webApi?: WebApiStructure
  oidc?: OidcStructure
}

export type ServerRetrievalMethodOptions = {
  webApi?: WebApi
  oidc?: Oidc
}

export class ServerRetrievalMethod extends CborStructure {
  public webApi?: WebApi
  public oidc?: Oidc

  public constructor(options: ServerRetrievalMethodOptions) {
    super()
    this.webApi = options.webApi
    this.oidc = options.oidc
  }

  public encodedStructure(): ServerRetrievalMethodStructure {
    const structure: ServerRetrievalMethodStructure = {}

    if (this.webApi) {
      structure.webApi = this.webApi.encodedStructure()
    }

    if (this.oidc) {
      structure.oidc = this.oidc.encodedStructure()
    }

    return structure
  }

  public static override fromEncodedStructure(
    encodedStructure: ServerRetrievalMethodStructure | Map<string, unknown>
  ): ServerRetrievalMethod {
    let structure = encodedStructure as ServerRetrievalMethodStructure

    if (encodedStructure instanceof Map) {
      structure = {
        webApi: encodedStructure.get('webApi') as ServerRetrievalMethodStructure['webApi'],
        oidc: encodedStructure.get('oidc') as ServerRetrievalMethodStructure['oidc'],
      }
    }

    return new ServerRetrievalMethod({
      webApi: structure.webApi ? WebApi.fromEncodedStructure(structure.webApi) : undefined,
      oidc: structure.oidc ? Oidc.fromEncodedStructure(structure.oidc) : undefined,
    })
  }
}
