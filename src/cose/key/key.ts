import { concatBytes } from '@noble/curves/abstract/utils'
import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import {
  CoseDNotDefinedError,
  CoseInvalidKtyForRawError,
  CoseInvalidValueForKtyError,
  CoseXNotDefinedError,
} from '../error'
import type { Curve } from './curve'
import { coseKeyToJwk, coseOptionsJwkMap, jwkCoseOptionsMap, jwkToCoseKey } from './jwk'
import type { KeyOps } from './key-operation'
import { KeyType } from './key-type'

export enum CoseKeyParameter {
  KeyType = 1,
  KeyId = 2,
  Algorithm = 3,
  KeyOps = 4,
  BaseIv = 5,

  // EC Key
  Curve = -1,
  X = -2,
  Y = -3,
  D = -4,
}

export type CoseKeyStructure = {
  [CoseKeyParameter.KeyType]: KeyType | string
  [CoseKeyParameter.KeyId]?: Uint8Array
  [CoseKeyParameter.Algorithm]?: string | number
  [CoseKeyParameter.KeyOps]?: Array<KeyOps | string>
  [CoseKeyParameter.BaseIv]?: Uint8Array

  [CoseKeyParameter.Curve]?: Curve
  [CoseKeyParameter.X]?: Uint8Array
  [CoseKeyParameter.Y]?: Uint8Array

  [CoseKeyParameter.D]?: Uint8Array
}

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
}

export class CoseKey extends CborStructure {
  public keyType: KeyType | string
  public keyId?: Uint8Array
  public algorithm?: string | number
  public keyOps?: Array<KeyOps | string>
  public baseIv?: Uint8Array

  public curve?: Curve
  public x?: Uint8Array
  public y?: Uint8Array

  public d?: Uint8Array

  public constructor(options: CoseKeyOptions) {
    super()
    this.keyType = options.keyType
    this.keyId = options.keyId
    this.algorithm = options.algorithm
    this.keyOps = options.keyOps
    this.baseIv = options.baseIv

    this.curve = options.curve
    this.x = options.x
    this.y = options.y
    this.d = options.d
  }

  public encodedStructure(): CoseKeyStructure {
    const structure: CoseKeyStructure = { [CoseKeyParameter.KeyType]: this.keyType }

    if (this.keyId) {
      structure[CoseKeyParameter.KeyId] = this.keyId
    }

    if (this.algorithm) {
      structure[CoseKeyParameter.Algorithm] = this.algorithm
    }

    if (this.keyOps) {
      structure[CoseKeyParameter.KeyOps] = this.keyOps
    }

    if (this.baseIv) {
      structure[CoseKeyParameter.BaseIv] = this.baseIv
    }

    if (this.curve) {
      structure[CoseKeyParameter.Curve] = this.curve
    }

    if (this.x) {
      structure[CoseKeyParameter.X] = this.x
    }

    if (this.y) {
      structure[CoseKeyParameter.Y] = this.y
    }

    if (this.d) {
      structure[CoseKeyParameter.D] = this.d
    }

    return structure
  }

  public static fromJwk(jwk: Record<string, unknown>) {
    if (!('kty' in jwk)) {
      throw new CoseInvalidValueForKtyError('JWK does not contain required kty value')
    }

    const options = Object.entries(jwk).reduce(
      (prev, [key, value]) => ({
        ...prev,
        [jwkCoseOptionsMap[key] ?? key]:
          typeof jwkToCoseKey[key as keyof typeof jwkToCoseKey] === 'function'
            ? jwkToCoseKey[key as keyof typeof jwkToCoseKey](value)
            : undefined,
      }),
      {} as CoseKeyOptions
    )

    return new CoseKey(options)
  }

  public static override fromEncodedStructure(encodedStructure: CoseKeyStructure | Map<unknown, unknown>): CoseKey {
    let structure = encodedStructure as CoseKeyStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as CoseKeyStructure
    }

    return new CoseKey({
      keyType: structure[CoseKeyParameter.KeyType],
      keyId: structure[CoseKeyParameter.KeyId],
      algorithm: structure[CoseKeyParameter.Algorithm],
      keyOps: structure[CoseKeyParameter.KeyOps],
      baseIv: structure[CoseKeyParameter.BaseIv],
      curve: structure[CoseKeyParameter.Curve],
      x: structure[CoseKeyParameter.X],
      y: structure[CoseKeyParameter.Y],
      d: structure[CoseKeyParameter.D],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): CoseKey {
    const structure = cborDecode<Map<unknown, unknown>>(bytes, options)
    return CoseKey.fromEncodedStructure(structure)
  }

  public get publicKey() {
    if (this.keyType !== KeyType.Ec) {
      throw new CoseInvalidKtyForRawError()
    }

    if (!this.x) {
      throw new CoseXNotDefinedError()
    }

    if (!this.y) {
      throw new CoseXNotDefinedError()
    }

    return concatBytes(Uint8Array.from([0x04]), this.x, this.y)
  }

  public get privateKey() {
    if (this.keyType !== KeyType.Ec) {
      throw new CoseInvalidKtyForRawError()
    }

    if (!this.d) {
      throw new CoseDNotDefinedError()
    }

    return this.d
  }

  public get jwk(): Record<string, unknown> {
    return Object.entries(this).reduce(
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
