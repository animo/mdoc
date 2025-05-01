import { CborStructure } from '../../cbor'

export type OidcStructure = [number, string, string]

export type OidcOptions = {
  version: number
  issuerUrl: string
  serverRetrievalToken: string
}

export class Oidc extends CborStructure {
  public version: number
  public issuerUrl: string
  public serverRetrievalToken: string

  public constructor(options: OidcOptions) {
    super()
    this.version = options.version
    this.issuerUrl = options.issuerUrl
    this.serverRetrievalToken = options.serverRetrievalToken
  }

  public encodedStructure(): OidcStructure {
    return [this.version, this.issuerUrl, this.serverRetrievalToken]
  }

  public static override fromEncodedStructure(encodedStructure: OidcStructure): Oidc {
    return new Oidc({
      version: encodedStructure[0],
      issuerUrl: encodedStructure[1],
      serverRetrievalToken: encodedStructure[2],
    })
  }
}
