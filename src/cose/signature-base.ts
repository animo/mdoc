// import { CoseError } from './e-cose.js'
import type { Algorithm } from './headers.js'
// import { AlgorithmNames, Header } from './headers.js'
// import { validateAlgorithms } from './validate-algorithms.js'
//
export interface VerifyOptions {
  externalAAD?: Uint8Array
  detachedPayload?: Uint8Array
  algorithms?: Algorithm[]
}

// type SignatureBaseOptions = {
//   protectedHeaders: Map<number, unknown> | Uint8Array
//   unprotectedHeaders: Map<number, unknown>
//   signature: Uint8Array
// }

// export class SignatureBase {
//   public protectedHeaders: Map<number, unknown> | Uint8Array
//   public unprotectedHeaders: Map<number, unknown>
//   public signature: Uint8Array
//
//   /**
//       This parameter is used to indicate the algorithm used for the
//       security processing.  This parameter MUST be authenticated where
//       the ability to do so exists.  This support is provided by AEAD
//       algorithms or construction (COSE_Sign, COSE_Sign0, COSE_Mac, and
//       COSE_Mac0).  This authentication can be done either by placing the
//       header in the protected header bucket or as part of the externally
//       supplied data.  The value is taken from the "COSE Algorithms"
//       registry (see Section 16.4).
//    */
//   public get alg(): Algorithm | undefined {
//     return (
//       (this.protectedHeaders.get(Header.Algorithm) as Algorithm | undefined) ??
//       (this.unprotectedHeaders.get(Header.Algorithm) as Algorithm)
//     )
//   }
//
//   public get algName(): string | undefined {
//     return this.alg ? AlgorithmNames.get(this.alg) : undefined
//   }
//
//   /**
//       This parameter identifies one piece of data that can be used as
//       input to find the needed cryptographic key.  The value of this
//       parameter can be matched against the 'kid' member in a COSE_Key
//       structure.  Other methods of key distribution can define an
//       equivalent field to be matched.  Applications MUST NOT assume that
//       'kid' values are unique.  There may be more than one key with the
//       same 'kid' value, so all of the keys associated with this 'kid'
//       may need to be checked.  The internal structure of 'kid' values is
//       not defined and cannot be relied on by applications.  Key
//       identifier values are hints about which key to use.  This is not a
//       security-critical field.  For this reason, it can be placed in the
//       unprotected headers bucket.
//    */
//   public get kid(): Uint8Array | undefined {
//     return (
//       (this.protectedHeaders.get(Header.KeyID) as Uint8Array | undefined) ??
//       (this.unprotectedHeaders.get(Header.KeyID) as Uint8Array)
//     )
//   }
//
//   public get x5chain(): [Uint8Array, ...Uint8Array[]] | undefined {
//     const x5chain =
//       (this.protectedHeaders.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined) ??
//       (this.unprotectedHeaders.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined)
//
//     if (!x5chain?.[0]) {
//       return undefined
//     }
//     return Array.isArray(x5chain) ? (x5chain as [Uint8Array, ...Uint8Array[]]) : [x5chain]
//   }
//
//   protected internalGetRawVerificationData(payload: Uint8Array, options?: VerifyOptions) {
//     if (!this.alg || !this.algName || !AlgorithmNames.has(this.alg)) {
//       throw new CoseError({
//         code: 'COSE_UNSUPPORTED_ALG',
//         message: `Unsupported alg '${this.alg}'`,
//       })
//     }
//
//     const algorithms = options?.algorithms && validateAlgorithms('algorithms', options.algorithms)
//
//     if (algorithms && !algorithms.has(this.alg)) {
//       throw new CoseError({
//         code: 'COSE_INVALID_ALG',
//         message: `[${Header.Algorithm}] (algorithm) Header Parameter not allowed`,
//       })
//     }
//
//     return {
//       alg: this.algName,
//       signature: this.signature,
//       data: payload,
//     }
//   }
// }
