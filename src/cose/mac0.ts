import { CborStructure } from '../cbor/cbor-structure.js'
import { CborEncodeError } from '../cbor/error.js'
import { type CborDecodeOptions, addExtension } from '../cbor/index.js'
import { cborDecode, cborEncode } from '../cbor/parser.js'
import { CoseInvalidAlgorithm, CosePayloadMustBeDefined } from './error.js'
import { Header, type MacAlgorithm, MacAlgorithmNames } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { UnprotectedHeaders, type UnprotectedHeadersOptions } from './headers/unprotected-headers.js'

export type Mac0Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

export type Mac0Options = {
  protectedHeaders: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders: UnprotectedHeaders | UnprotectedHeadersOptions['unprotectedHeaders']
  payload?: Uint8Array | null
  tag?: Uint8Array
  externalAad?: Uint8Array
  detachedContent?: Uint8Array
}

export class Mac0 extends CborStructure {
  public static tag = 17

  public protectedHeaders: ProtectedHeaders
  public unprotectedHeaders: UnprotectedHeaders
  public payload: Uint8Array | null
  public tag?: Uint8Array

  public externalAad?: Uint8Array
  public detachedContent?: Uint8Array

  public constructor(options: Mac0Options) {
    super()

    this.protectedHeaders =
      options.protectedHeaders instanceof ProtectedHeaders
        ? options.protectedHeaders
        : new ProtectedHeaders({ protectedHeaders: options.protectedHeaders })

    this.unprotectedHeaders =
      options.unprotectedHeaders instanceof UnprotectedHeaders
        ? options.unprotectedHeaders
        : new UnprotectedHeaders({ unprotectedHeaders: options.unprotectedHeaders })

    this.payload = options.payload ?? null

    this.tag = options.tag

    this.externalAad = options.externalAad
    this.detachedContent = options.detachedContent
  }

  public encodedStructure(): Mac0Structure {
    if (!this.tag) {
      throw new CborEncodeError('Tag must be defined when trying to encode a Mac0 structure')
    }

    return [
      this.protectedHeaders.encodedStructure(),
      this.unprotectedHeaders.encodedStructure(),
      this.payload,
      this.tag,
    ]
  }

  public get toBeAuthenticated() {
    const payload = this.detachedContent ?? this.payload

    if (!payload) {
      throw new CosePayloadMustBeDefined()
    }

    const toBeAuthenticated: Array<unknown> = ['MAC0', this.protectedHeaders]

    if (this.externalAad) toBeAuthenticated.push(this.externalAad)

    toBeAuthenticated.push(payload)

    return cborEncode(toBeAuthenticated)
  }

  public get signatureAlgorithmName() {
    const algorithm =
      this.protectedHeaders.headers?.get(Header.Algorithm) ?? this.unprotectedHeaders.headers?.get(Header.Algorithm)

    if (!algorithm) {
      throw new CoseInvalidAlgorithm()
    }

    const algorithmName = MacAlgorithmNames.get(algorithm as MacAlgorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithm()
    }

    return algorithmName
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    return cborDecode<Mac0>(bytes, options)
  }

  public static override fromEncodedStructure(encodedStructure: Mac0Structure): Mac0 {
    return new Mac0({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      tag: encodedStructure[3],
    })
  }
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  // TODO: why is the tag not being used?
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.encodedStructure())
  },
  decode: Mac0.fromEncodedStructure,
})
