import type { JWK } from 'jose'
import { cborDecode, cborEncode } from '../../cbor/index.js'
import { base64url, bytesToString, concatBytes } from '../../utils/transformers.js'
import { CoseError } from '../error.js'
import { Algorithm } from '../headers'
import { TypedMap } from '../typed-map.js'
import { Curve } from './curve.js'
import type { KeyOps } from './key-ops.js'
import { JWKKeyOps, JWKKeyOpsToCOSE } from './key-ops.js'
import type { KeyType } from './kty.js'
import { JwkKeyType } from './kty.js'
import { CoseKeyParam, JwkParam, KtySpecificJwkParams, KtySpecificJwkParamsReveverse } from './params.js'

const toArray = (v: unknown | unknown[]) => (Array.isArray(v) ? v : [v])

function normalize(input: string | Uint8Array): string {
  return input instanceof Uint8Array ? bytesToString(input) : input
}

// @ts-ignore
export const JwkFromCoseValue = new Map<string, (v: unknown) => string>([
  ['kty', (value: KeyType) => JwkKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithm) => Algorithm[value]],
  ['kid', (v: string | Uint8Array) => (typeof v === 'string' ? v : base64url.encode(v))],
  ['key_ops', (v) => toArray(v).map((value) => JWKKeyOps.get(value))],
  ...['x', 'y', 'd', 'k'].map((param) => [param, base64url.encode]),
])

export const JwkToCoseValue = new Map<string, (v: unknown) => KeyType | Uint8Array | Algorithm | KeyOps[]>([
  ['kty', (value: JwkKeyType) => JwkKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithm) => Algorithm[value]],
  ['kid', (v: unknown) => v],
  ['key_ops', (v: unknown) => toArray(v).flatMap((value) => JWKKeyOpsToCOSE.get(value))],
  ...['x', 'y', 'd', 'k'].map((label) => [label, (v: Uint8Array | string) => base64url.decode(normalize(v))]),
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
] as any)

export class CoseKey extends TypedMap<
  | [CoseKeyParam.KeyType, KeyType]
  | [CoseKeyParam.KeyID, Uint8Array]
  | [CoseKeyParam.Algorithm, Algorithm]
  | [CoseKeyParam.KeyOps, KeyOps[]]
  | [CoseKeyParam.BaseIV, Uint8Array]
  | [CoseKeyParam.Curve, Curve]
  | [CoseKeyParam.x, Uint8Array]
  | [CoseKeyParam.y, Uint8Array]
  | [CoseKeyParam.d, Uint8Array]
  | [CoseKeyParam.k, Uint8Array]
> {
  /**
   * Import a COSEKey either decoded as Map<number, unknown> or as an encoded CBOR.
   */
  static import(data: Uint8Array | Map<number, unknown>): CoseKey {
    if (data instanceof Uint8Array) {
      return new CoseKey(cborDecode(data))
    }
    return new CoseKey(data as ConstructorParameters<typeof CoseKey>[0])
  }

  /**
   * Create a COSEKey from a JWK.
   */
  static fromJWK(jwk: JWK): CoseKey {
    const coseKey = new CoseKey()
    const kty = jwk.kty
    for (const [key, value] of Object.entries(jwk)) {
      const jwkKey = KtySpecificJwkParamsReveverse[kty]?.get(key) ?? (JwkParam[key as keyof typeof JwkParam] as number)
      const formatter = JwkToCoseValue.get(key)
      if (jwkKey && formatter) {
        coseKey.set(jwkKey, formatter(value))
      }
    }
    return coseKey
  }

  /**
   * Returns a JWK representation of the COSEKey.
   */
  toJWK(): JWK {
    const kty = JwkKeyType[this.get(CoseKeyParam.KeyType) as unknown as JwkKeyType]
    const result: JWK = { kty }

    for (const [key, value] of this) {
      const jwkKey = KtySpecificJwkParams[kty]?.get(key) ?? JwkParam[key]
      const parser = JwkFromCoseValue.get(jwkKey)
      if (parser && jwkKey) {
        const parsed = parser(value)
        // @ts-expect-error JWK has no index signature
        result[jwkKey] = parsed
      }
    }
    return result
  }

  /**
   * Encode the COSEKey as a CBOR buffer.
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
 */
export const COSEKeyToRAW = (key: Map<number, Uint8Array | number> | Uint8Array): Uint8Array => {
  const decodedKey = key instanceof Uint8Array ? cborDecode<Map<number, Uint8Array | number>>(key) : key

  const kty = decodedKey.get(CoseKeyParam.KeyType)
  if (kty !== 2) {
    throw new Error(`Expected COSE Key type: EC2 (2), got: ${kty}`)
  }

  const d = decodedKey.get(CoseKeyParam.d)
  if (d && d instanceof Uint8Array) {
    return d
  }

  const x = decodedKey.get(CoseKeyParam.x)
  const y = decodedKey.get(CoseKeyParam.y)

  if (!(x instanceof Uint8Array)) {
    throw new CoseError({
      code: 'COSE_INVALID_TYPE_FOR_KEY',
      message: `Cose key x and y value are not a byte array. Received ${x}`,
    })
  }

  if (!(y instanceof Uint8Array)) {
    throw new CoseError({
      code: 'COSE_INVALID_TYPE_FOR_KEY',
      message: `Cose key x and y value are not a byte array. Received ${y}`,
    })
  }

  return concatBytes([Uint8Array.from([0x04]), x, y])
}
