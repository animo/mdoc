import type { JWK } from 'jose'
import type { MdocContext } from '../../c-mdoc.js'
import { DataItem, cborDecode, cborEncode } from '../../cbor/index.js'
import { Algorithm, Header } from '../../cose/headers.js'
import { ProtectedHeaders } from '../../cose/headers/protected-headers.js'
import { UnprotectedHeaders } from '../../cose/headers/unprotected-headers.js'
import { COSEKey } from '../../cose/key/cose-key.js'
import { stringToUint8Array } from '../../u-uint8-array.js'
import { IssuerSignedItem } from '../issuer-signed-item.js'
import { fromPEM } from '../utils.js'
import { IssuerAuth } from './issuer-auth.js'
import { IssuerSignedDocument } from './issuer-signed-document.js'
import type {
  DeviceKeyInfo,
  DigestAlgorithm,
  DocType,
  IssuerNameSpaces,
  MSO,
  SupportedAlgs,
  ValidityInfo,
} from './types.js'
function isObjectLike(value: unknown) {
  return typeof value === 'object' && value !== null
}

export default function isObject(input: unknown): input is Record<string, unknown> {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
    return false
  }
  if (Object.getPrototypeOf(input) === null) {
    return true
  }
  let proto = input
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto)
  }
  return Object.getPrototypeOf(input) === proto
}

const addYears = (date: Date, years: number): Date => {
  const r = new Date(date.getTime())
  r.setFullYear(date.getFullYear() + years)
  return r
}

/**
 * Use this class when building new documents.
 *
 * This class allow you to build a document and sign it with the issuer's private key.
 */
export class Document {
  readonly docType: DocType
  #issuerNameSpaces: IssuerNameSpaces = new Map()
  #deviceKeyInfo?: DeviceKeyInfo
  #validityInfo: ValidityInfo = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
  }
  #digestAlgorithm: DigestAlgorithm = 'SHA-256'
  ctx: { crypto: MdocContext['crypto'] }

  constructor(doc: DocType, ctx: { crypto: MdocContext['crypto'] }) {
    this.docType = doc
    this.ctx = ctx
  }

  /**
   * Add a namespace to an unsigned document.
   */
  addIssuerNameSpace(namespace: 'org.iso.18013.5.1' | (string & {}), values: Record<string, unknown>): Document {
    const namespaceRecord = this.#issuerNameSpaces.get(namespace) ?? []

    const addAttribute = (key: string, value: unknown) => {
      const digestID = namespaceRecord.length
      const issuerSignedItem = IssuerSignedItem.create(digestID, key, value, this.ctx)
      namespaceRecord.push(issuerSignedItem)
    }

    for (const [key, value] of Object.entries(values)) {
      addAttribute(key, value)
    }

    this.#issuerNameSpaces.set(namespace, namespaceRecord)

    return this
  }

  /**
   * Get the values in a namespace.
   */
  getIssuerNameSpace(namespace: string): Record<string, unknown> | undefined {
    const nameSpace = this.#issuerNameSpaces.get(namespace)
    if (!nameSpace) return undefined
    return Object.fromEntries(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]))
  }

  /**
   * Add the device public key which will be include in the issuer signature.
   * The device public key could be in JWK format or as COSE_Key format.
   */
  addDeviceKeyInfo({ deviceKey }: { deviceKey: JWK | Uint8Array }): Document {
    const deviceKeyCOSEKey = deviceKey instanceof Uint8Array ? deviceKey : COSEKey.fromJWK(deviceKey).encode()
    const decodedCoseKey = cborDecode<Map<number, number>>(deviceKeyCOSEKey)

    this.#deviceKeyInfo = {
      deviceKey: decodedCoseKey,
    }

    return this
  }

  /**
   * Add validity info to the document that will be used in the issuer signature.
   *
   * @param info - the validity info
   * @param {Date} [info.signed] - The date the document is signed. default: now
   * @param {Date} [info.validFrom] - The date the document is valid from. default: signed
   * @param {Date} [info.validUntil] - The date the document is valid until. default: signed + 1 year
   * @param {Date} [info.expectedUpdate] - The date the document is expected to be updated. default: null
   * @returns
   */
  addValidityInfo(info: Partial<ValidityInfo> = {}): Document {
    const signed = info.signed ?? new Date()
    const validFrom = info.validFrom ?? signed
    const validUntil = info.validUntil ?? addYears(signed, 1)
    this.#validityInfo = {
      signed,
      validFrom,
      validUntil,
    }

    // We don't want an undefined value to end up in the CBOR
    if (info.expectedUpdate) {
      this.#validityInfo.expectedUpdate = info.expectedUpdate
    }

    return this
  }

  /**
   * Set the digest algorithm used for the value digests in the issuer signature.
   *
   * The default is SHA-256.
   */
  useDigestAlgorithm(digestAlgorithm: DigestAlgorithm): Document {
    this.#digestAlgorithm = digestAlgorithm
    return this
  }

  /**
   * Generate the issuer signature for the document.
   */
  async sign(
    params: {
      issuerPrivateKey: JWK
      issuerCertificate: string | Uint8Array
      alg: SupportedAlgs
      kid?: string | Uint8Array
    },
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<IssuerSignedDocument> {
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added')
    }

    const issuerPublicKeyBuffer =
      typeof params.issuerCertificate === 'string' ? fromPEM(params.issuerCertificate) : params.issuerCertificate

    const issuerPrivateKeyJWK =
      params.issuerPrivateKey instanceof Uint8Array
        ? COSEKey.import(params.issuerPrivateKey).toJWK()
        : params.issuerPrivateKey

    const valueDigests = new Map(
      await Promise.all(
        Array.from(this.#issuerNameSpaces.entries()).map(async ([namespace, items]) => {
          const digestMap = new Map<number, Uint8Array>()
          await Promise.all(
            items.map(async (item, index) => {
              const hash = await item.calculateDigest(this.#digestAlgorithm, ctx)
              digestMap.set(index, new Uint8Array(hash))
            })
          )
          return [namespace, digestMap] as [string, Map<number, Uint8Array>]
        })
      )
    )

    const mso: MSO = {
      version: '1.0',
      digestAlgorithm: this.#digestAlgorithm,
      valueDigests,
      deviceKeyInfo: this.#deviceKeyInfo,
      docType: this.docType,
      validityInfo: this.#validityInfo,
    }

    const payload = cborEncode(DataItem.fromData(mso))

    const _kid = params.kid ?? issuerPrivateKeyJWK.kid
    const kid = typeof _kid === 'string' ? stringToUint8Array(_kid) : _kid
    const headers = new Map(
      kid
        ? [
            [Header.KeyID, kid],
            [Header.X5Chain, issuerPublicKeyBuffer],
          ]
        : [[Header.X5Chain, issuerPublicKeyBuffer]]
    )

    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, Algorithm[params.alg]]]),
    })
    const unprotectedHeaders = new UnprotectedHeaders({ unprotectedHeaders: headers })

    const issuerAuth = new IssuerAuth({ unprotectedHeaders, protectedHeaders, payload })

    const signature = await ctx.cose.sign1.sign({
      sign1: issuerAuth,
      jwk: issuerPrivateKeyJWK,
    })
    issuerAuth.signature = signature

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    }

    return new IssuerSignedDocument(this.docType, issuerSigned)
  }
}
