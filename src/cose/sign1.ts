import { CborEncodeError } from '../cbor/error.js'
import { type CborDecodeOptions, CborStructure, addExtension, cborDecode, cborEncode } from '../cbor/index.js'
import { CoseInvalidAlgorithm, CosePayloadMustBeDefined } from './error.js'
import { type SignatureAlgorithm, SignatureAlgorithmNames, Header } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { type UnprotectedHeaderOptions, UnprotectedHeaders } from './headers/unprotected-headers.js'

export type Sign1Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

export type Sign1Options = {
  protectedHeaders: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
  payload?: Uint8Array | null
  signature?: Uint8Array

  detachedContent?: Uint8Array
  externalAad?: Uint8Array
}

export class Sign1 extends CborStructure {
  public static tag = 18

  public protectedHeaders: ProtectedHeaders
  public unprotectedHeaders: UnprotectedHeaders
  public payload: Uint8Array | null
  public signature?: Uint8Array

  public detachedContent?: Uint8Array
  public externalAad?: Uint8Array

  public constructor(options: Sign1Options) {
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
    this.signature = options.signature

    this.detachedContent = options.detachedContent
    this.externalAad = options.externalAad
  }

  public encodedStructure(): Sign1Structure {
    if (!this.signature) {
      throw new CborEncodeError('Signature must be defined when trying to encode a Sign1 structure')
    }

    return [
      this.protectedHeaders.encodedStructure(),
      this.unprotectedHeaders.encodedStructure(),
      this.payload,
      this.signature,
    ]
  }

  public get toBeSigned() {
    const payload = this.detachedContent ?? this.payload

    if (!payload) {
      throw new CosePayloadMustBeDefined()
    }

    const toBeSigned: Array<unknown> = ['Signature1', this.protectedHeaders]

    if (this.externalAad) toBeSigned.push(this.externalAad)

    toBeSigned.push(payload)

    return cborEncode(toBeSigned)
  }

  public get signatureAlgorithmName() {
    const algorithm =
      this.protectedHeaders.headers?.get(Header.Algorithm) ?? this.unprotectedHeaders.headers?.get(Header.Algorithm)

    if (!algorithm) {
      throw new CoseInvalidAlgorithm()
    }

    const algorithmName = SignatureAlgorithmNames.get(algorithm as SignatureAlgorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithm()
    }

    return algorithmName
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    return cborDecode<Sign1>(bytes, options)
  }

  public static override fromEncodedStructure(encodedStructure: Sign1Structure): Sign1 {
    return new Sign1({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  // TODO: why is the tag not being used?
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.encodedStructure())
  },
  decode: Sign1.fromEncodedStructure,
})
