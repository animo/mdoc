import { cborDecode, cborEncode } from '../cbor/index.js'

export class COSEBase {
  #encodedProtectedHeaders?: Uint8Array
  public readonly protectedHeaders: Map<number, unknown>

  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeaders: Map<number, unknown>
  ) {
    if (protectedHeaders instanceof Uint8Array) {
      this.#encodedProtectedHeaders = protectedHeaders
      this.protectedHeaders =
        protectedHeaders.length === 0 ? new Map<number, unknown>() : cborDecode<Map<number, unknown>>(protectedHeaders)
    } else {
      this.protectedHeaders = protectedHeaders
      this.#encodedProtectedHeaders = cborEncode(protectedHeaders)
    }
  }

  protected get encodedProtectedHeaders(): Uint8Array | undefined {
    return this.#encodedProtectedHeaders
  }
  public encode() {
    return cborEncode(this)
  }
}
