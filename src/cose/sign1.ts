import { type CborDecodeOptions, CborStructure, addExtension, cborDecode, cborEncode } from '../cbor/index.js'
import { CoseError } from './e-cose.js'
import { type Algorithm, AlgorithmNames, Header } from './headers.js'
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

  public encodedStructure(): unknown {
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
      throw new CoseError({
        code: 'COSE_PAYLOAD_MUST_BE_DEFINED',
        message: 'Payload was not provided, nor was detached content',
      })
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
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: 'Could not find the algorithm in the protected or unprotected headers',
      })
    }
    const algorithmName = AlgorithmNames.get(algorithm as Algorithm)
    if (!algorithmName) {
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: `Found algorithm with id '${algorithm}', but could not map this to a name`,
      })
    }
    return algorithmName
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    return cborDecode<Sign1>(bytes, options)
  }
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  // TODO: why is the tag not being used?
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.encodedStructure())
  },
  decode: (data: Sign1Structure) => {
    return new Sign1({ protectedHeaders: data[0], unprotectedHeaders: data[1], payload: data[2], signature: data[3] })
  },
})
