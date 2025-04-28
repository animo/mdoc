import { concatBytes } from '@noble/curves/abstract/utils'
import { type CborDecodeOptions, CborStructure, cborDecode } from '../cbor'
import { CoseDNotDefined, CoseInvalidKtyForRaw, CoseXNotDefined } from './error'

export enum KeyOps {
  Sign = 1,
  Verify = 2,
  Encrypt = 3,
  Decrypt = 4,
  WrapKey = 5,
  UnwrapKey = 6,
  DeriveKey = 7,
  DeriveBits = 8,
  MACCreate = 9,
  MACVerify = 10,
}

export enum KeyType {
  Okp = 1,
  Ec = 2,
  Oct = 4,
  Reserved = 0,
}

export enum Curve {
  'P-256' = 1,
  'P-384' = 2,
  'P-521' = 3,
  X25519 = 4,
  X448 = 5,
  Ed25519 = 6,
  Ed448 = 7,
}

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
      throw new CoseInvalidKtyForRaw()
    }

    if (!this.x) {
      throw new CoseXNotDefined()
    }

    if (!this.y) {
      throw new CoseXNotDefined()
    }

    return concatBytes(Uint8Array.from([0x04]), this.x, this.y)
  }

  public get privateKey() {
    if (this.keyType !== KeyType.Ec) {
      throw new CoseInvalidKtyForRaw()
    }

    if (!this.d) {
      throw new CoseDNotDefined()
    }

    return this.d
  }
}
