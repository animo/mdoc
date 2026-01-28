import { concatBytes } from '@noble/curves/utils.js'
import { z } from 'zod'
import { CborStructure } from '../../cbor'
import { typedMap } from '../../utils'
import { zUint8Array } from '../../utils/zod'
import {
  CoseDNotDefinedError,
  CoseInvalidKtyForRawError,
  CoseInvalidValueForKtyError,
  CoseKeyTypeNotSupportedForPrivateKeyExtractionError,
  CoseKNotDefinedError,
  CoseXNotDefinedError,
  CoseYNotDefinedError,
} from '../error'
import { Curve } from './curve'
import { coseKeyToJwk, coseOptionsJwkMap, jwkCoseOptionsMap, jwkToCoseKey } from './jwk'
import { KeyOps } from './key-operation'
import { KeyType } from './key-type'

export enum CoseKeyParameter {
  KeyType = 1,
  KeyId = 2,
  Algorithm = 3,
  KeyOps = 4,
  BaseIv = 5,

  // EC Key or Oct with K
  CurveOrK = -1,
  X = -2,
  Y = -3,
  D = -4,
}

// Zod schema for CoseKey validation
const coseKeySchema = typedMap([
  [CoseKeyParameter.KeyType, z.union([z.enum(KeyType), z.string()])],
  [CoseKeyParameter.KeyId, zUint8Array.exactOptional()],
  [CoseKeyParameter.Algorithm, z.union([z.string(), z.number()]).exactOptional()],
  [CoseKeyParameter.KeyOps, z.array(z.union([z.enum(KeyOps), z.string()])).exactOptional()],
  [CoseKeyParameter.BaseIv, zUint8Array.exactOptional()],
  [CoseKeyParameter.CurveOrK, z.union([z.enum(Curve), zUint8Array]).exactOptional()],
  [CoseKeyParameter.X, zUint8Array.exactOptional()],
  [CoseKeyParameter.Y, zUint8Array.exactOptional()],
  [CoseKeyParameter.D, zUint8Array.exactOptional()],
] as const)

// Infer structure type from Zod schema
export type CoseKeyDecodedStructure = z.output<typeof coseKeySchema>
export type CoseKeyEncodedStructure = z.input<typeof coseKeySchema>

// Manual options type (user-facing API)
export type CoseKeyOptions = {
  keyType: KeyType | string
  keyId?: Uint8Array
  algorithm?: string | number
  keyOps?: Array<KeyOps | string>
  baseIv?: Uint8Array

  curve?: Curve
  x?: Uint8Array
  y?: Uint8Array

  d?: Uint8Array

  k?: Uint8Array
}

export class CoseKey extends CborStructure<CoseKeyEncodedStructure, CoseKeyDecodedStructure> {
  public static override get encodingSchema() {
    return coseKeySchema
  }

  public get keyType() {
    return this.structure.get(CoseKeyParameter.KeyType)
  }

  public get keyId() {
    return this.structure.get(CoseKeyParameter.KeyId)
  }

  public get algorithm() {
    return this.structure.get(CoseKeyParameter.Algorithm)
  }

  public get keyOps() {
    return this.structure.get(CoseKeyParameter.KeyOps)
  }

  public get baseIv() {
    return this.structure.get(CoseKeyParameter.BaseIv)
  }

  public get curve() {
    if (this.keyType === KeyType.Ec || this.keyType === KeyType.Okp) {
      // Casting is needed, as it can be both Curve or K
      return this.structure.get(CoseKeyParameter.CurveOrK) as Curve | undefined
    }

    return undefined
  }

  public get x() {
    return this.structure.get(CoseKeyParameter.X)
  }

  public get y() {
    return this.structure.get(CoseKeyParameter.Y)
  }

  public get d() {
    return this.structure.get(CoseKeyParameter.D)
  }

  public get k() {
    if (this.keyType === KeyType.Oct) {
      return this.structure.get(CoseKeyParameter.CurveOrK) as Uint8Array | undefined
    }
    return undefined
  }

  public static create(options: CoseKeyOptions): CoseKey {
    const entries: Array<[CoseKeyParameter, unknown]> = [[CoseKeyParameter.KeyType, options.keyType]]

    if (options.keyId !== undefined) {
      entries.push([CoseKeyParameter.KeyId, options.keyId])
    }

    if (options.algorithm !== undefined) {
      entries.push([CoseKeyParameter.Algorithm, options.algorithm])
    }

    if (options.keyOps !== undefined) {
      entries.push([CoseKeyParameter.KeyOps, options.keyOps])
    }

    if (options.baseIv !== undefined) {
      entries.push([CoseKeyParameter.BaseIv, options.baseIv])
    }

    if (options.curve !== undefined) {
      entries.push([CoseKeyParameter.CurveOrK, options.curve])
    }

    if (options.x !== undefined) {
      entries.push([CoseKeyParameter.X, options.x])
    }

    if (options.y !== undefined) {
      entries.push([CoseKeyParameter.Y, options.y])
    }

    if (options.d !== undefined) {
      entries.push([CoseKeyParameter.D, options.d])
    }

    if (options.k !== undefined) {
      entries.push([CoseKeyParameter.CurveOrK, options.k])
    }

    return this.fromEncodedStructure(new Map(entries))
  }

  // TODO: add jwk zod schema
  public static fromJwk(jwk: Record<string, unknown>) {
    if (!('kty' in jwk)) {
      throw new CoseInvalidValueForKtyError('JWK does not contain required kty value')
    }

    const options = Object.entries(jwk).reduce((prev, [key, value]) => {
      const mappedKey = jwkCoseOptionsMap[key] ?? key

      const mapFunction = jwkToCoseKey[key as keyof typeof jwkToCoseKey]
      const convertedValue = mapFunction ? mapFunction(value) : value

      // Only include if value is not undefined
      if (convertedValue !== undefined) {
        return { ...prev, [mappedKey]: convertedValue }
      }

      return prev
    }, {} as CoseKeyOptions)

    return CoseKey.create(options)
  }

  public get publicKey() {
    if (this.keyType !== KeyType.Ec) {
      throw new CoseInvalidKtyForRawError()
    }

    if (!this.x) {
      throw new CoseXNotDefinedError()
    }

    if (!this.y) {
      throw new CoseYNotDefinedError()
    }

    return concatBytes(Uint8Array.from([0x04]), this.x, this.y)
  }

  public get privateKey() {
    if (this.keyType === KeyType.Ec) {
      if (!this.d) {
        throw new CoseDNotDefinedError()
      }

      return this.d
    }

    if (this.keyType === KeyType.Oct) {
      if (!this.k) {
        throw new CoseKNotDefinedError()
      }

      return this.k
    }

    throw new CoseKeyTypeNotSupportedForPrivateKeyExtractionError()
  }

  public get jwk(): Record<string, unknown> {
    // Convert CoseKey properties to JWK format
    const options: CoseKeyOptions = {
      keyType: this.keyType,
      keyId: this.keyId,
      algorithm: this.algorithm,
      keyOps: this.keyOps,
      baseIv: this.baseIv,
      curve: this.curve,
      x: this.x,
      y: this.y,
      d: this.d,
      k: this.k,
    }

    return Object.entries(options).reduce(
      (prev, [key, value]) => ({
        ...prev,
        [coseOptionsJwkMap[key] ?? key]:
          typeof coseKeyToJwk[key as keyof typeof coseKeyToJwk] === 'function'
            ? // @ts-ignore
              coseKeyToJwk[key as keyof typeof coseKeyToJwk](value)
            : undefined,
      }),
      {}
    )
  }
}
