import { CborEncodeError } from '../cbor/error.js'
import { type CborDecodeOptions, CborStructure, addExtension, cborDecode, cborEncode } from '../cbor/index.js'
import type { MdocContext } from '../context.js'
import { CoseCertificateNotFoundError, CoseInvalidAlgorithmError, CosePayloadMustBeDefinedError } from './error.js'
import { Header, type SignatureAlgorithm } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { UnprotectedHeaders, type UnprotectedHeadersOptions } from './headers/unprotected-headers.js'
import { coseKeyToJwk } from './key/jwk.js'
import type { CoseKey } from './key/key.js'

export type Sign1Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

export type Sign1Options = {
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeadersOptions['unprotectedHeaders']
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

  public get certificateChain() {
    return this.x5chain ?? []
  }

  public get certificate() {
    const [certificate] = this.certificateChain

    if (!certificate) {
      throw new CoseCertificateNotFoundError()
    }

    return certificate
  }

  public getIssuingCountry(ctx: { x509: MdocContext['x509'] }) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0]

    return countryName
  }

  public getIssuingStateOrProvince(ctx: { x509: MdocContext['x509'] }) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0]

    return stateOrProvince
  }

  public get toBeSigned() {
    const payload = this.detachedContent ?? this.payload

    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const toBeSigned: Array<unknown> = [
      'Signature1',
      this.protectedHeaders.encodedStructure(),
      this.externalAad ?? new Uint8Array(),
      payload,
    ]

    return cborEncode(toBeSigned)
  }

  public get signatureAlgorithmName(): string {
    const algorithm = (this.protectedHeaders.headers?.get(Header.Algorithm) ??
      this.unprotectedHeaders.headers?.get(Header.Algorithm)) as SignatureAlgorithm | undefined

    if (!algorithm) {
      throw new CoseInvalidAlgorithmError()
    }

    const algorithmName = coseKeyToJwk.algorithm(algorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithmName
  }

  public get x5chain() {
    const x5chain =
      (this.protectedHeaders.headers?.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined) ??
      (this.unprotectedHeaders.headers?.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined)

    if (!x5chain?.[0]) {
      return undefined
    }

    return Array.isArray(x5chain) ? x5chain : [x5chain]
  }

  public async addSignature(options: { signingKey: CoseKey }, ctx: { cose: MdocContext['cose'] }) {
    const payload = this.payload ?? this.detachedContent
    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const signature = await ctx.cose.sign1.sign({
      sign1: this,
      key: options.signingKey,
    })

    this.signature = signature
  }

  public async verify(options: { key?: CoseKey }, ctx: { cose: MdocContext['cose']; x509: MdocContext['x509'] }) {
    const publicKey =
      options.key ??
      (await ctx.x509.getPublicKey({
        certificate: this.certificate,
        alg: this.signatureAlgorithmName,
      }))

    return await ctx.cose.sign1.verify({
      sign1: this,
      key: publicKey,
    })
  }

  public static fromEncodedSignature1(signature1: Uint8Array) {
    const structure = cborDecode<[string, Uint8Array, Uint8Array, Uint8Array]>(signature1, { mapsAsObjects: false })

    return new Sign1({
      protectedHeaders: ProtectedHeaders.decode(structure[1]),
      externalAad: structure[2],
      payload: structure[3],
    })
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
    return encodeFn(instance)
  },
  decode: Sign1.fromEncodedStructure,
})
