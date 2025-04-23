import type { JWK } from 'jose'
import type { Mac0 } from './cose/mac0.js'
import type { Sign1 } from './cose/sign1.js'
import type { VerifyOptions } from './cose/signature-base.js'
import type { DigestAlgorithm } from './mdoc/model/types.js'

export type MaybePromise<TType> = Promise<TType> | TType

export interface X509Context {
  getIssuerNameField: (input: {
    certificate: Uint8Array
    field: string
  }) => string[]
  getPublicKey: (input: {
    certificate: Uint8Array
    alg: string
  }) => MaybePromise<JWK>
  validateCertificateChain: (input: {
    trustedCertificates: Uint8Array[]
    x5chain: Uint8Array[]
  }) => MaybePromise<void>
  getCertificateData: (input: { certificate: Uint8Array }) => MaybePromise<{
    issuerName: string
    subjectName: string
    serialNumber: string
    thumbprint: string
    notBefore: Date
    notAfter: Date
    pem: string
  }>
}

export interface MdocContext {
  crypto: {
    random: (length: number) => Uint8Array
    digest: (input: {
      digestAlgorithm: DigestAlgorithm
      bytes: Uint8Array
    }) => MaybePromise<Uint8Array>
    /**
     * Calculates the ephemeral mac key for the device authentication.
     *
     * There are two cases for this function:
     * 1. SDeviceKey.Priv and EReaderKey.Pub for the mdoc
     * 2. EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader
     */
    calculateEphemeralMacKeyJwk: (input: {
      privateKey: Uint8Array
      publicKey: Uint8Array
      sessionTranscriptBytes: Uint8Array
    }) => MaybePromise<JWK>
  }
  cose: {
    sign1: {
      sign: (input: { sign1: Sign1; jwk: JWK }) => MaybePromise<Uint8Array>

      verify(input: {
        jwk: JWK
        options?: VerifyOptions
        sign1: Sign1
      }): MaybePromise<boolean>
    }

    mac0: {
      sign: (input: { jwk: JWK; mac0: Mac0 }) => MaybePromise<Uint8Array>

      verify(input: {
        mac0: Mac0
        jwk: JWK
        options?: VerifyOptions
      }): MaybePromise<boolean>
    }
  }

  x509: X509Context
}
