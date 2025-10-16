import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { CoseKey, IssuerSigned, SignatureAlgorithm } from '../src'
import { IssuerSignedBuilder } from '../src/mdoc/builders'
import { mdocContext } from './context'
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from './issuing/config'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

describe('Issue And Verify', () => {
  let encodedIssuerSigned: string

  test('issue mdoc with signature', async () => {
    const isb = new IssuerSignedBuilder('org.iso.18013.5.1', mdocContext)

    isb.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      family_name: 'Doe',
    })

    const issuerSigned = await isb.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })

    encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    expect(issuerSigned.getPrettyClaims('org.iso.18013.5.1.mDL')).toEqual({
      family_name: 'Doe',
    })

    const isSignatureValid = await issuerSigned.issuerAuth.verifySignature({}, mdocContext)

    expect(isSignatureValid).toBeTruthy()
  })

  test('receive mdoc', async () => {
    const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    const isSignatureValid = await issuerSigned.issuerAuth.verifySignature({}, mdocContext)
    expect(isSignatureValid).toBeTruthy()
  })
})
