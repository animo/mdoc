export enum Header {
  Algorithm = 1,
  Critical = 2,
  ContentType = 3,
  KeyID = 4,
  IV = 5,
  PartialIV = 6,
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

export type Direct = -6

export type SupportedEncryptionAlgorithm = 'A128GCM' | 'A192GCM' | 'A256GCM'

export const EncryptionAlgorithmNames = new Map<EncryptionAlgorithm, SupportedEncryptionAlgorithm>([
  [EncryptionAlgorithm.A128GCM, 'A128GCM'],
  [EncryptionAlgorithm.A192GCM, 'A192GCM'],
  [EncryptionAlgorithm.A256GCM, 'A256GCM'],
])

export const MacAlgorithmNames = new Map<MacAlgorithm, SupportedMacAlgorithms>([
  [MacAlgorithm.HS256, 'HS256'],
  [MacAlgorithm.HS384, 'HS384'],
  [MacAlgorithm.HS512, 'HS512'],
])

export const SignatureAlgorithmNames = new Map<SignatureAlgorithm, SupportedSignatureAlgorithms>([
  [SignatureAlgorithm.EdDSA, 'EdDSA'],
  [SignatureAlgorithm.ES256, 'ES256'],
  [SignatureAlgorithm.ES384, 'ES384'],
  [SignatureAlgorithm.ES512, 'ES512'],
  [SignatureAlgorithm.PS256, 'PS256'],
  [SignatureAlgorithm.PS384, 'PS384'],
  [SignatureAlgorithm.PS512, 'PS512'],
  [SignatureAlgorithm.RS256, 'RS256'],
  [SignatureAlgorithm.RS384, 'RS384'],
  [SignatureAlgorithm.RS512, 'RS512'],
])

// @todo remove these?
export type SupportedMacAlgorithms = 'HS256' | 'HS384' | 'HS512'

export type SupportedSignatureAlgorithms =
  | 'EdDSA'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
