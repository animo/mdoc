import { CborStructure } from '../cbor/cbor-structure.js'
import { type CborDecodeOptions, addExtension } from '../cbor/index.js'
import { cborDecode, cborEncode } from '../cbor/parser.js'
import { CoseError } from './error.js'
import { type Algorithm, AlgorithmNames, Header } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { type UnprotectedHeaderOptions, UnprotectedHeaders } from './headers/unprotected-headers.js'

export type Mac0Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

export type Mac0Options = {
  protectedHeaders: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
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

  public encodedStructure(): unknown {
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
      throw new CoseError({
        code: 'COSE_PAYLOAD_MUST_BE_DEFINED',
        message: 'Payload was not provided, nor was detached content',
      })
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
    return cborDecode<Mac0>(bytes, options)
  }
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  // TODO: why is the tag not being used?
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.encodedStructure())
  },
  decode: (data: Mac0Structure) => {
    return new Mac0({ protectedHeaders: data[0], unprotectedHeaders: data[1], payload: data[2], tag: data[3] })
  },
})
