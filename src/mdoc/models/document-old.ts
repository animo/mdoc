import { DataItem, cborDecode, cborEncode } from '../../cbor/index.js'
import type { MdocContext } from '../../context.js'
import { Header, SignatureAlgorithm } from '../../cose/headers/defaults.js'
import { ProtectedHeaders } from '../../cose/headers/protected-headers.js'
import { UnprotectedHeaders } from '../../cose/headers/unprotected-headers.js'
import { CoseKey } from '../../cose/key/key.js'
import { stringToBytes } from '../../utils/transformers.js'
import { IssuerSignedItem } from '../issuer-signed-item.js'
import { fromPem } from '../utils.js'
import { IssuerAuth } from './issuer-auth.js'
import { IssuerSignedDocument } from './issuer-signed-document.js'
import type {
  DeviceKeyInfoOld,
  DigestAlgorithm,
  DocTypeOld,
  IssuerNameSpaces,
  MSO,
  SupportedAlgs,
  ValidityInfoOld,
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
export class DocumentOld {
  readonly docType: DocTypeOld
  #issuerNameSpaces: IssuerNameSpaces = new Map()
  #deviceKeyInfo?: DeviceKeyInfoOld
  #validityInfo: ValidityInfoOld = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
  }
  #digestAlgorithm: DigestAlgorithm = 'SHA-256'
  ctx: { crypto: MdocContext['crypto'] }

  constructor(doc: DocTypeOld, ctx: { crypto: MdocContext['crypto'] }) {
    this.docType = doc
    this.ctx = ctx
  }

  /**
   * Add a namespace to an unsigned document.
   */
  addIssuerNameSpace(namespace: 'org.iso.18013.5.1' | (string & {}), values: Record<string, unknown>): DocumentOld {
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

  getIssuerNameSpace(namespace: string): Record<string, unknown> | undefined {
    const nameSpace = this.#issuerNameSpaces.get(namespace)
    if (!nameSpace) return undefined
    return Object.fromEntries(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]))
  }

  addDeviceKeyInfo({ deviceKey }: { deviceKey: Record<string, unknown> | Uint8Array }): DocumentOld {
    const deviceKeyCOSEKey = deviceKey instanceof Uint8Array ? deviceKey : CoseKey.fromJwk(deviceKey).encode()
    const decodedCoseKey = cborDecode<Map<number, number>>(deviceKeyCOSEKey)

    this.#deviceKeyInfo = {
      deviceKey: decodedCoseKey,
    }

    return this
  }
  addValidityInfo(info: Partial<ValidityInfoOld> = {}): DocumentOld {
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
  useDigestAlgorithm(digestAlgorithm: DigestAlgorithm): DocumentOld {
    this.#digestAlgorithm = digestAlgorithm
    return this
  }

  /**
   * Generate the issuer signature for the document.
   */
  async sign(
    params: {
      issuerPrivateKey: Record<string, unknown>
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
      typeof params.issuerCertificate === 'string' ? fromPem(params.issuerCertificate) : params.issuerCertificate

    const issuerPrivateKeyJwk = CoseKey.fromJwk(params.issuerPrivateKey).jwk

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

    const _kid = params.kid ?? issuerPrivateKeyJwk.kid
    const kid = typeof _kid === 'string' ? stringToBytes(_kid) : _kid
    const headers = new Map(
      kid
        ? [
            [Header.KeyID, kid],
            [Header.X5Chain, issuerPublicKeyBuffer],
          ]
        : [[Header.X5Chain, issuerPublicKeyBuffer]]
    )

    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, SignatureAlgorithm[params.alg]]]),
    })
    const unprotectedHeaders = new UnprotectedHeaders({ unprotectedHeaders: headers })

    const issuerAuth = new IssuerAuth({ unprotectedHeaders, protectedHeaders, payload })

    const signature = await ctx.cose.sign1.sign({
      sign1: issuerAuth,
      jwk: issuerPrivateKeyJwk,
    })
    issuerAuth.signature = signature

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    }

    return new IssuerSignedDocument(this.docType, issuerSigned)
  }
}
