import type { JWK } from 'jose'
import { cborDecode, cborEncode } from '../../cbor/index.js'
import { base64UrlToUint8Array, uint8ArrayToBase64Url } from '../../u-base64.js'
import { concatUint8Array, uint8ArrayToString } from '../../u-uint8-array.js'
import { Algorithm } from '../headers.js'
import { TypedMap } from '../typed-map.js'
import { Curve } from './curve.js'
import type { KeyOps } from './key-ops.js'
import { JWKKeyOps, JWKKeyOpsToCOSE } from './key-ops.js'
import type { KeyType } from './kty.js'
import { JWKKeyType } from './kty.js'
import { COSEKeyParam, JWKParam, KTYSpecificJWKParams, KTYSpecificJWKParamsRev } from './params.js'

const toArray = (v: unknown | unknown[]) => (Array.isArray(v) ? v : [v])

function normalize(input: string | Uint8Array): string {
  const encoded = input
  if (encoded instanceof Uint8Array) {
    return uint8ArrayToString(encoded)
  }
  return encoded
}
// @ts-ignore
export const JWKFromCOSEValue = new Map<string, (v: unknown) => string>([
  ['kty', (value: KeyType) => JWKKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithm) => Algorithm[value]],
  ['kid', (v: string | Uint8Array) => (typeof v === 'string' ? v : uint8ArrayToBase64Url(v))],
  ['key_ops', (v) => toArray(v).map((value) => JWKKeyOps.get(value))],
  ...['x', 'y', 'd', 'k'].map((param) => [param, (v: Uint8Array) => uint8ArrayToBase64Url(v)]),
])

export const JWKToCOSEValue = new Map<string, (v: unknown) => KeyType | Uint8Array | Algorithm | KeyOps[]>([
  ['kty', (value: JWKKeyType) => JWKKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithm) => Algorithm[value]],
  ['kid', (v: unknown) => v],
  ['key_ops', (v: unknown) => toArray(v).flatMap((value) => JWKKeyOpsToCOSE.get(value))],
  ...['x', 'y', 'd', 'k'].map((label) => [
    label,
    (v: Uint8Array | string) => {
      const normalized = normalize(v)
      return base64UrlToUint8Array(normalized)
    },
  ]),
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
] as any)

export class COSEKey extends TypedMap<
  | [COSEKeyParam.KeyType, KeyType]
  | [COSEKeyParam.KeyID, Uint8Array]
  | [COSEKeyParam.Algorithm, Algorithm]
  | [COSEKeyParam.KeyOps, KeyOps[]]
  | [COSEKeyParam.BaseIV, Uint8Array]
  | [COSEKeyParam.Curve, Curve]
  | [COSEKeyParam.x, Uint8Array]
  | [COSEKeyParam.y, Uint8Array]
  | [COSEKeyParam.d, Uint8Array]
  | [COSEKeyParam.k, Uint8Array]
> {
  /**
   * Import a COSEKey either decoded as Map<number, unknown> or as an encoded CBOR.
   *
   * @param data {Uint8Array | Map<number, unknown>}
   * @returns
   */
  static import(data: Uint8Array | Map<number, unknown>): COSEKey {
    if (data instanceof Uint8Array) {
      return new COSEKey(cborDecode(data))
    }
    return new COSEKey(data as ConstructorParameters<typeof COSEKey>[0])
  }

  /**
   *
   * Create a COSEKey from a JWK.
   *
   * @param jwk {JWK} - A JWK.
   * @returns
   */
  static fromJWK(jwk: JWK): COSEKey {
    const coseKey = new COSEKey()
    const kty = jwk.kty
    for (const [key, value] of Object.entries(jwk)) {
      const jwkKey = KTYSpecificJWKParamsRev[kty]?.get(key) ?? (JWKParam[key as keyof typeof JWKParam] as number)
      const formatter = JWKToCOSEValue.get(key)
      if (jwkKey && formatter) {
        coseKey.set(jwkKey, formatter(value))
      }
    }
    return coseKey
  }

  /**
   *
   * Returns a JWK representation of the COSEKey.
   *
   * @returns {JWK} - The JWK representation of the COSEKey.
   */
  toJWK(): JWK {
    const kty = JWKKeyType[this.get(COSEKeyParam.KeyType) as unknown as JWKKeyType]
    const result: JWK = { kty }

    for (const [key, value] of this) {
      const jwkKey = KTYSpecificJWKParams[kty]?.get(key) ?? JWKParam[key]
      const parser = JWKFromCOSEValue.get(jwkKey)
      if (parser && jwkKey) {
        const parsed = parser(value)
        // @ts-expect-error JWK has no index signature
        result[jwkKey] = parsed
      }
    }
    return result
  }

  /**
   *
   * Encode the COSEKey as a CBOR buffer.
   *
   * @returns {Uint8Array} - The encoded COSEKey.
   */
  encode(): Uint8Array {
    return cborEncode(this.esMap)
  }
}

/**
 * Exports the COSE Key as a raw key.
 *
 * It's effectively the same than:
 *
 * crypto.subtle.exportKey('raw', importedJWK)
 *
 * Note: This only works for KTY = EC.
 *
 * @param {Map<number, Uint8Array | number>} key - The COSE Key
 * @returns {Uint8Array} - The raw key
 */
export const COSEKeyToRAW = (key: Map<number, Uint8Array | number> | Uint8Array): Uint8Array => {
  let decodedKey: Map<number, Uint8Array | number>
  if (key instanceof Uint8Array) {
    decodedKey = cborDecode(key)
  } else {
    decodedKey = key
  }
  const kty = decodedKey.get(1)
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`)
  }

  // its a private key
  if (decodedKey.has(-4)) {
    return decodedKey.get(-4) as Uint8Array
  }

  return concatUint8Array(Uint8Array.from([0x04]), decodedKey.get(-2) as Uint8Array, decodedKey.get(-3) as Uint8Array)
}
