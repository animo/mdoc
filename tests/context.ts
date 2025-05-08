import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha2'
import { hkdf } from '@panva/hkdf'
import * as x509 from '@peculiar/x509'
import { X509Certificate } from '@peculiar/x509'
import { base64url, exportJWK, importX509 } from 'jose'
import { CoseKey, type MdocContext, type X509Context, hex, stringToBytes } from '../src'

export const mdocContext: MdocContext = {
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes)
      return new Uint8Array(digest)
    },
    random: (length: number) => {
      return crypto.getRandomValues(new Uint8Array(length))
    },
    calculateEphemeralMacKeyJwk: async (input) => {
      const { privateKey, publicKey, sessionTranscriptBytes, info } = input
      const ikm = p256.getSharedSecret(hex.encode(privateKey), hex.encode(publicKey), true).slice(1)
      const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', sessionTranscriptBytes))
      const infoAsBytes = stringToBytes(info)
      const digest = 'sha256'
      const result = await hkdf(digest, ikm, salt, infoAsBytes, 32)

      return {
        key_ops: ['sign', 'verify'],
        ext: true,
        kty: 'oct',
        k: base64url.encode(result),
        alg: 'HS256',
      }
    },
  },

  cose: {
    mac0: {
      sign: async (input) => {
        const { jwk, mac0 } = input
        const tba = mac0.toBeAuthenticated
        const key = await crypto.subtle.importKey('jwk', jwk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
        return new Uint8Array(await crypto.subtle.sign('HMAC', key, tba))
      },
      verify: async (input) => {
        const { mac0, jwk } = input
        const { tag, toBeAuthenticated } = mac0
        if (!tag) {
          throw new Error('tag is required for mac0 verification')
        }
        const key = await crypto.subtle.importKey('jwk', jwk, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
        return crypto.subtle.verify('HMAC', key, tag, toBeAuthenticated)
      },
    },
    sign1: {
      sign: async (input) => {
        const { key, sign1 } = input

        const hashed = sha256(sign1.toBeSigned)
        const sig = p256.sign(hashed, key.privateKey)

        return sig.toCompactRawBytes()
      },
      verify: async (input) => {
        const { sign1, jwk } = input
        const { toBeSigned, signature } = sign1

        if (!signature) {
          throw new Error('signature is required for sign1 verification')
        }

        const hashed = sha256(toBeSigned)
        return p256.verify(signature, hashed, CoseKey.fromJwk(jwk).publicKey)
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

      return (await exportJWK(key)) as unknown as Record<string, unknown>
    },

    validateCertificateChain: async (input: {
      trustedCertificates: Array<Uint8Array>
      x5chain: Array<Uint8Array>
    }) => {
      const { trustedCertificates, x5chain: certificateChain } = input
      if (certificateChain.length === 0) throw new Error('Certificate chain is empty')

      const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0])

      const parsedCertificates = certificateChain.map((c) => new x509.X509Certificate(c))

      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: parsedCertificates,
      })

      const chain = await certificateChainBuilder.build(parsedLeafCertificate)

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      let parsedChain = chain.map((c) => new x509.X509Certificate(c.rawData)).reverse()

      if (parsedChain.length !== certificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
      }

      const parsedTrustedCertificates = trustedCertificates.map(
        (trustedCertificate) => new x509.X509Certificate(trustedCertificate)
      )

      const trustedCertificateIndex = parsedChain.findIndex((cert) =>
        parsedTrustedCertificates.some((tCert) => cert.equal(tCert))
      )

      if (trustedCertificateIndex === -1) {
        throw new Error('No trusted certificate was found while validating the X.509 chain')
      }

      // Pop everything off above the index of the trusted as it is not relevant for validation
      parsedChain = parsedChain.slice(0, trustedCertificateIndex)

      // Verify the certificate with the publicKey of the certificate above
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i]
        const previousCertificate = parsedChain[i - 1]
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined
        await cert?.verify({ publicKey, date: new Date() })
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
  } satisfies X509Context,
}
