/**
 * COSE Header labels registered in the IANA "COSE Header Parameters" registry.
 * Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
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

export enum Algorithm {
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

export const MacAlgorithmNames = new Map<MacAlgorithm, SupportedMacAlg>([
  [MacAlgorithm.HS256, 'HS256'],
  [MacAlgorithm.HS384, 'HS384'],
  [MacAlgorithm.HS512, 'HS512'],
])

export const AlgorithmNames = new Map<Algorithm, SupportedSignatureAlg>([
  [Algorithm.EdDSA, 'EdDSA'],
  [Algorithm.ES256, 'ES256'],
  [Algorithm.ES384, 'ES384'],
  [Algorithm.ES512, 'ES512'],
  [Algorithm.PS256, 'PS256'],
  [Algorithm.PS384, 'PS384'],
  [Algorithm.PS512, 'PS512'],
  [Algorithm.RS256, 'RS256'],
  [Algorithm.RS384, 'RS384'],
  [Algorithm.RS512, 'RS512'],
])

export type SupportedMacAlg = 'HS256' | 'HS384' | 'HS512'

export type SupportedSignatureAlg =
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

// export class ProtectedHeaders extends TypedMap<
//   | [Header.Algorithm, Algorithm]
//   | [Header.Critical, Header[]]
//   | [Header.ContentType, number | Uint8Array]
//   | [Header.KeyID, Uint8Array]
//   | [
//       Omit<Header, Header.Algorithm | Header.Critical | Header.ContentType | Header.KeyID>,
//       Uint8Array | Uint8Array[] | number | number[],
//     ]
// > {
//   /**
//    * Ensure input is a ProtectedHeaders instance.
//    *
//    * @param headers - The headers to wrap.
//    * @returns
//    */
//   static from(headers: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0]) {
//     //similar to base class wrap
//     if (headers instanceof ProtectedHeaders) {
//       return headers
//     }
//     return new ProtectedHeaders(headers)
//   }
//
//   /**
//    * CBOR encode the hedaers instance
//    * @returns {Uint8Array} - The encoded protected headers.
//    */
//   encode(): Uint8Array {
//     return cborEncode(this.esMap)
//   }
// }
//

//
// export class EncryptProtectedHeaders extends TypedMap<
//   | [Header.Algorithm, EncryptionAlgorithm]
//   | [Header.Critical, Header[]]
//   | [Header.ContentType, number | Uint8Array]
//   | [Header.KeyID, Uint8Array]
//   | [
//       Omit<Header, Header.Algorithm | Header.Critical | Header.ContentType | Header.KeyID>,
//       Uint8Array | number | number[],
//     ]
// > {
//   /**
//    * Ensure input is a EncryptProtectedHeaders instance.
//    *
//    * @param headers - The headers to wrap.
//    * @returns
//    */
//   static from(headers: EncryptProtectedHeaders | ConstructorParameters<typeof EncryptProtectedHeaders>[0]) {
//     //similar to base class wrap
//     if (headers instanceof EncryptProtectedHeaders) {
//       return headers
//     }
//     return new MacProtectedHeaders(headers)
//   }
// }
//
// export class MacProtectedHeaders extends TypedMap<
//   | [Header.Algorithm, MacAlgorithm]
//   | [Header.Critical, Header[]]
//   | [Header.ContentType, number | Uint8Array]
//   | [Header.KeyID, Uint8Array]
//   | [
//       Omit<Header, Header.Algorithm | Header.Critical | Header.ContentType | Header.KeyID>,
//       Uint8Array | number | number[],
//     ]
// > {
//   /**
//    * Ensure input is a MacProtectedHeaders instance.
//    *
//    * @param headers - The headers to wrap.
//    * @returns
//    */
//   static from(headers: MacProtectedHeaders | ConstructorParameters<typeof MacProtectedHeaders>[0]) {
//     //similar to base class wrap
//     if (headers instanceof MacProtectedHeaders) {
//       return headers
//     }
//     return new MacProtectedHeaders(headers)
//   }
// }
//
// export class UnprotectedHeaders extends TypedMap<
//   | [Header.ContentType, number | Uint8Array]
//   | [Header.KeyID, Uint8Array]
//   | [Header.IV, Uint8Array]
//   | [Header.PartialIV, Uint8Array]
//   | [Header.X5Chain, Uint8Array | Uint8Array[]]
//   | [
//       Exclude<Header, Header.ContentType | Header.KeyID | Header.PartialIV | Header.X5Chain>,
//       number | number[] | Uint8Array | Uint8Array[],
//     ]
// > {
//   /**
//    * Ensure input is a MacProtectedHeaders instance.
//    *
//    * @param headers - The headers to wrap.
//    * @returns
//    */
//   static from(headers: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0]) {
//     //similar to base class wrap
//     if (headers instanceof UnprotectedHeaders) {
//       return headers
//     }
//     return new UnprotectedHeaders(headers)
//   }
// }
