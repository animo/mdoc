import { CborStructure } from '../../cbor'

export type WebApiStructure = [number, string, string]

export type WebApiOptions = {
  version: number
  issuerUrl: string
  serverRetrievalToken: string
}

export class WebApi extends CborStructure {
  public version: number
  public issuerUrl: string
  public serverRetrievalToken: string

  public constructor(options: WebApiOptions) {
    super()
    this.version = options.version
    this.issuerUrl = options.issuerUrl
    this.serverRetrievalToken = options.serverRetrievalToken
  }

  public encodedStructure(): WebApiStructure {
    return [this.version, this.issuerUrl, this.serverRetrievalToken]
  }

  public static override fromEncodedStructure(encodedStructure: WebApiStructure): WebApi {
    return new WebApi({
      version: encodedStructure[0],
      issuerUrl: encodedStructure[1],
      serverRetrievalToken: encodedStructure[2],
    })
  }
}
