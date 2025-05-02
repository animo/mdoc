export enum Header {
  Algorithm = 1,
  Critical = 2,
  ContentType = 3,
  KeyId = 4,
  Iv = 5,
  PartialIv = 6,
  CounterSignature = 7,
  CounterSignature0 = 9,
  CounterSignatureV2 = 11,
  CounterSignature0V2 = 12,
  X5Bag = 32,
  X5Chain = 33,
  X5T = 34,
  X5U = 35,
}

export enum SignatureAlgorithm {
  EdDSA = -8,
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
}

export enum MacAlgorithm {
  HS256 = 5,
  HS384 = 6,
  HS512 = 7,
}

export enum EncryptionAlgorithm {
  A128GCM = 1,
  A192GCM = 2,
  A256GCM = 3,
  Direct = -6,
}
