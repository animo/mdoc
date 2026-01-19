import crypto from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@panva/hkdf'
import * as x509 from '@peculiar/x509'
import { X509Certificate } from '@peculiar/x509'
import { exportJWK, importX509 } from 'jose'
import { CoseKey, hex, KeyOps, KeyType, MacAlgorithm, type MdocContext, stringToBytes } from '../src'

export const mdocContext: MdocContext = {
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes)
      return new Uint8Array(digest)
    },
    random: (length: number) => {
      return crypto.getRandomValues(new Uint8Array(length))
    },
    calculateEphemeralMacKey: async (input) => {
      const { privateKey, publicKey, sessionTranscriptBytes, info } = input
      const ikm = p256.getSharedSecret(privateKey, publicKey, true).slice(1)
      const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', sessionTranscriptBytes))
      const infoAsBytes = stringToBytes(info)
      const digest = 'sha256'
      const result = await hkdf(digest, ikm, salt, infoAsBytes, 32)

      return new CoseKey({
        keyOps: [KeyOps.Sign, KeyOps.Verify],
        keyType: KeyType.Oct,
        k: result,
        algorithm: MacAlgorithm.HS256,
      })
    },
  },

  cose: {
    mac0: {
      sign: async (input) => {
        const { key, mac0 } = input
        return hmac(sha256, key.privateKey, mac0.toBeAuthenticated)
      },
      verify: async (input) => {
        const { mac0, key } = input

        if (!mac0.tag) {
          throw new Error('tag is required for mac0 verification')
        }

        return mac0.tag === hmac(sha256, key.privateKey, mac0.toBeAuthenticated)
      },
    },
    sign1: {
      sign: async (input) => {
        const { key, sign1 } = input
        return p256.sign(sign1.toBeSigned, key.privateKey, { format: 'compact' })
      },
      verify: async (input) => {
        const { sign1, key } = input
        const { toBeSigned, signature } = sign1

        if (!signature) {
          throw new Error('signature is required for sign1 verification')
        }

        // lowS is needed after upgrade of @noble/curves to keep existing tests passing
        return p256.verify(signature, toBeSigned, key.publicKey, { lowS: false })
      },
    },
  },

  x509: {
    getIssuerNameField: (input: { certificate: Uint8Array; field: string }) => {
      const certificate = new X509Certificate(input.certificate)
      return certificate.issuerName.getField(input.field)
    },
    getPublicKey: async (input: { certificate: Uint8Array; alg: string }) => {
      const certificate = new X509Certificate(input.certificate)

      const key = await importX509(certificate.toString(), input.alg, {
        extractable: true,
      })

      return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>)
    },

    verifyCertificateChain: async (input: {
      trustedCertificates: Array<Uint8Array>
      x5chain: Array<Uint8Array>
      now?: Date
    }) => {
      const { trustedCertificates, x5chain: mdocCertificateChain } = input
      if (mdocCertificateChain.length === 0) throw new Error('Certificate chain is empty')

      const parsedLeafCertificate = new x509.X509Certificate(mdocCertificateChain[0])
      const parsedMdocCertificates = mdocCertificateChain.map((c) => new x509.X509Certificate(c))
      const parsedTrustedCertificates = trustedCertificates.map((c) => new x509.X509Certificate(c))

      // Use both trusted and mdoc certificate to build chain
      const certificatesToBuildChain = [...parsedMdocCertificates, ...parsedTrustedCertificates]
      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: certificatesToBuildChain,
      })

      const chain = await certificateChainBuilder.build(parsedLeafCertificate)

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      let parsedChain = chain.map((c) => new x509.X509Certificate(c.rawData)).reverse()

      // We allow longer parsed chain, in case the root cert was not part of the chain, but in the
      // list of trusted certificates
      if (parsedChain.length < mdocCertificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
      }

      const trustedCertificateIndex = parsedChain.findIndex((cert) =>
        parsedTrustedCertificates.some((tCert) => cert.equal(tCert))
      )

      if (trustedCertificateIndex === -1) {
        throw new Error('No trusted certificate was found while validating the X.509 chain')
      }

      // FIXME: we should remove this, and update all tests to use root cert for verification
      // as the 'correct' way to verify is only using the root
      // Currently if you provide a leaf certificate as trusted entities it will not verify any
      // certificate, as we don't have the root, and can't verify the leaf without the authority key
      // so basically it just does an equals match on whether the certificate is equal with a trusted
      // certificate. But that also means you skip verification of the validity time of the cert
      parsedChain = parsedChain.slice(0, trustedCertificateIndex)

      // Verify the certificate with the publicKey of the certificate above
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i]
        const previousCertificate = parsedChain[i - 1]
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined
        await cert?.verify({ publicKey, date: input.now ?? new Date() })
      }
    },
    getCertificateData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate)
      const thumbprint = await certificate.getThumbprint(crypto)
      const thumbprintHex = hex.encode(new Uint8Array(thumbprint))
      return {
        issuerName: certificate.issuerName.toString(),
        subjectName: certificate.subjectName.toString(),
        pem: certificate.toString(),
        serialNumber: certificate.serialNumber,
        thumbprint: thumbprintHex,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      }
    },
  },
}

export const deterministicMdocContext = {
  ...mdocContext,
  crypto: {
    ...mdocContext.crypto,
    random: (len: number) =>
      hex.decode('9bdb72498967865710108af43959f90c1b6aac9687bedd1fa53dd0d2103fa5d0').slice(0, len),
  },
}
