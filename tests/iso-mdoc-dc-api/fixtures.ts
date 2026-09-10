import { X509Certificate } from '@peculiar/x509'
import { CoseKey, DeviceKey, Issuer, type KeyAuthorizations, SignatureAlgorithm } from '../../src'
import { DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

export const RECIPIENT_JWK_PRIVATE = {
  kty: 'EC',
  crv: 'P-256',
  x: 'YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y',
  y: 'eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk',
  d: 'ya-p2EW6dRZrXCFXZ7HWk05Qw9s26JsSe4piKxIPZyE',
}

export const RECIPIENT_JWK_PUBLIC = {
  kty: RECIPIENT_JWK_PRIVATE.kty,
  crv: RECIPIENT_JWK_PRIVATE.crv,
  x: RECIPIENT_JWK_PRIVATE.x,
  y: RECIPIENT_JWK_PRIVATE.y,
}

export const issuerCertificate = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)

export const mdlDocType = 'org.iso.18013.5.1.mDL'
export const mdlNamespace = 'org.iso.18013.5.1'

export async function createIssuerSigned(options?: {
  docType?: string
  claims?: Record<string, unknown>
  keyAuthorizations?: KeyAuthorizations
}) {
  const docType = options?.docType ?? mdlDocType
  const issuer = new Issuer(docType, mdocContext)

  issuer.addIssuerNamespace(mdlNamespace, {
    family_name: 'Doe',
    given_name: 'John',
    birth_date: '1990-01-01',
    ...options?.claims,
  })

  const signed = new Date()
  const validFrom = new Date(signed.getTime() - 60_000)
  const validUntil = new Date(signed.getTime() + 365 * 24 * 60 * 60 * 1000)

  return await issuer.sign({
    signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    certificates: [issuerCertificate],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {
      deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC),
      ...(options?.keyAuthorizations && { keyAuthorizations: options.keyAuthorizations }),
    },
    validityInfo: { signed, validFrom, validUntil },
  })
}
