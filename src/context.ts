import type { CoseKey, DigestAlgorithm } from './cose/index.js'
import type { Mac0 } from './cose/mac0.js'
import type { Sign1 } from './cose/sign1.js'

type MaybePromise<T> = Promise<T> | T

export interface MdocContext {
  crypto: {
    random: (length: number) => Uint8Array
    digest: (input: {
      digestAlgorithm: DigestAlgorithm
      bytes: Uint8Array
    }) => MaybePromise<Uint8Array>
    calculateEphemeralMacKey: (input: {
      privateKey: Uint8Array
      publicKey: Uint8Array
      sessionTranscriptBytes: Uint8Array
      info: 'EMacKey' | 'SKReader' | 'SKDevice'
    }) => MaybePromise<CoseKey>
  }

  cose: {
    sign1: {
      sign: (input: { sign1: Sign1; key: CoseKey }) => MaybePromise<Uint8Array>

      verify(input: {
        key: CoseKey
        sign1: Sign1
      }): MaybePromise<boolean>
    }

    mac0: {
      sign: (input: { key: CoseKey; mac0: Mac0 }) => MaybePromise<Uint8Array>

      verify(input: {
        mac0: Mac0
        key: CoseKey
      }): MaybePromise<boolean>
    }
  }

  x509: {
    getIssuerNameField: (input: {
      certificate: Uint8Array
      field: string
    }) => string[]

    getPublicKey: (input: {
      certificate: Uint8Array
      alg: string
    }) => MaybePromise<CoseKey>

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
}
