import { type CborDecodeOptions, cborDecode, cborEncode } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'

export type Oid4vpDraft18HandoverStructure = [Uint8Array, Uint8Array, string]

export type Oid4vpDraft18HandoverOptions = {
  mdocGeneratedNonce?: string
  clientId?: string
  responseUri?: string
  nonce: string

  clientIdHash?: Uint8Array
  responseUriHash?: Uint8Array
}

/**
 *
 * @note this will be removed as it is already a legacy handover structure
 *
 */
export class Oid4vpDraft18Handover extends Handover {
  public mdocGeneratedNonce?: string
  public clientId?: string
  public responseUri?: string
  public nonce: string

  public clientIdHash?: Uint8Array
  public responseUriHash?: Uint8Array

  public constructor(options: Oid4vpDraft18HandoverOptions) {
    super()
    this.mdocGeneratedNonce = options.mdocGeneratedNonce
    this.clientId = options.clientId
    this.responseUri = options.responseUri
    this.nonce = options.nonce

    this.clientIdHash = options.clientIdHash
    this.responseUriHash = options.responseUriHash
  }

  public async prepare(ctx: Pick<MdocContext, 'crypto'>) {
    if (
      (!this.mdocGeneratedNonce || !this.clientId || !this.responseUri) &&
      (!this.clientIdHash || !this.responseUriHash)
    ) {
      throw new Error(
        'Either the responseUriHash and clientIdHash must be set or the clientId, responseUri and mdocGeneratedNonce'
      )
    }

    if (this.clientId && this.mdocGeneratedNonce) {
      this.clientIdHash = await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: cborEncode([this.clientId, this.mdocGeneratedNonce]),
      })
    }

    if (this.responseUri && this.mdocGeneratedNonce) {
      this.responseUriHash = await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: cborEncode([this.responseUri, this.mdocGeneratedNonce]),
      })
    }

    if (!this.clientIdHash || !this.responseUriHash) {
      throw new Error(
        'Could not hash the client id and/or the response uri. Make sure the properties are set on the class, or manually provide the hashed client id and response uri with the mdoc generated nonce'
      )
    }
  }

  public encodedStructure(): Oid4vpDraft18HandoverStructure {
    if (!this.clientIdHash || !this.responseUriHash) {
      throw new Error('Call `prepare` first to create the hash over the client id and response uri')
    }

    return [this.clientIdHash, this.responseUriHash, this.nonce]
  }

  public static override fromEncodedStructure(encodedStructure: Oid4vpDraft18HandoverStructure): Oid4vpDraft18Handover {
    return new Oid4vpDraft18Handover({
      clientIdHash: encodedStructure[0],
      responseUriHash: encodedStructure[1],
      nonce: encodedStructure[2],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpDraft18Handover {
    const structure = cborDecode<Oid4vpDraft18HandoverStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return Oid4vpDraft18Handover.fromEncodedStructure(structure)
  }

  public static isCorrectHandover(structure: unknown): structure is Oid4vpDraft18HandoverStructure {
    return (
      Array.isArray(structure) &&
      structure[0] instanceof Uint8Array &&
      structure[1] instanceof Uint8Array &&
      typeof structure[2] === 'string'
    )
  }
}
