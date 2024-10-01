import type { JWK } from 'jose';
import type { Mac0, VerifyOptions } from './cose/mac0.js';
import type { Sign1 } from './cose/sign1.js';
import type { VerifyOptions as Sign1VerifyOpts } from './cose/signature-base.js';
import type { DigestAlgorithm } from './mdoc/model/types.js';

export type MaybePromise<TType> = Promise<TType> | TType;

export interface X509Context {
  getIssuerName: (input: {
    certificate: Uint8Array;
  }) => NonNullable<unknown> | undefined;
  getIssuerNameField: (input: {
    certificate: Uint8Array;
    field: string;
  }) => string[];
  getPublicKey: (input: {
    certificate: Uint8Array;
    alg: string;
  }) => MaybePromise<JWK>;
  validateCertificateChain: (input: {
    certificates: [string, ...string[]];
  }) => MaybePromise<void>;
  getCertificateData: (input: { certificate: Uint8Array }) => MaybePromise<{
    subjectName: string;
    pem: string;
    serialNumber: string;
    thumbprint: string;
  }>;
  getCertificateValidityData: (input: {
    certificate: Uint8Array;
  }) => MaybePromise<{
    notBefore: Date;
    notAfter: Date;
  }>;
}

export interface MdocContext {
  crypto: {
    random: (length: number) => Promise<Uint8Array>;
    digest: (input: {
      digestAlgorithm: DigestAlgorithm;
      bytes: Uint8Array;
    }) => MaybePromise<Uint8Array>;
    /**
     * Calculates the ephemeral mac key for the device authentication.
     *
     * There are two cases for this function:
     * 1. SDeviceKey.Priv and EReaderKey.Pub for the mdoc
     * 2. EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader
     *
     * @param {Uint8Array} privateKey - The private key of the current party
     * @param {Uint8Array} publicKey - The public key of the other party
     * @param {Uint8Array} sessionTranscriptBytes - The session transcript bytes
     * @returns {Uint8Array} - The ephemeral mac key
     */
    calculateEphemeralMacKeyJwk: (input: {
      privateKey: Uint8Array;
      publicKey: Uint8Array;
      sessionTranscriptBytes: Uint8Array;
    }) => MaybePromise<JWK>;
  };
  cose: {
    sign1: {
      sign: (input: { sign1: Sign1; jwk: JWK }) => MaybePromise<Uint8Array>;

      verify(input: {
        jwk: JWK;
        options?: Sign1VerifyOpts | undefined;
        sign1: Sign1;
      }): MaybePromise<boolean>;
    };

    mac0: {
      sign: (input: { jwk: JWK; mac0: Mac0 }) => MaybePromise<Uint8Array>;

      verify(input: {
        mac0: Mac0;
        jwk: JWK;
        options: VerifyOptions;
      }): MaybePromise<boolean>;
    };
  };

  x509: X509Context;
}
