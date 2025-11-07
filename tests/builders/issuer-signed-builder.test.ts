import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { CoseKey, DateOnly, type IssuerSigned, SignatureAlgorithm } from '../../src'
import { IssuerSignedBuilder } from '../../src/mdoc/builders/issuer-signed-builder'
import { mdocContext } from '../context'
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../issuing/config'

const claims = {
  family_name: 'Jones',
  given_name: 'Ava',
  birth_date: new DateOnly('2007-03-25'),
  issue_date: new Date('2023-09-01'),
  expiry_date: new Date('2028-09-30'),
  issuing_country: 'US',
  issuing_authority: 'NY DMV',
  document_number: '01-856-5050',
  portrait: 'bstr',
  driving_privileges: [
    {
      vehicle_category_code: 'A',
      issue_date: new DateOnly('2021-09-02'),
      expiry_date: new DateOnly('2026-09-20'),
    },
    {
      vehicle_category_code: 'B',
      issue_date: new DateOnly('2022-09-02'),
      expiry_date: new DateOnly('2027-09-20'),
    },
  ],
}

describe('issuer signed builder', () => {
  let issuerSigned: IssuerSigned
  let _issuerSignedEncoded: Uint8Array

  const signed = new Date('2023-10-24T14:55:18Z')
  const validFrom = new Date(signed)
  validFrom.setMinutes(signed.getMinutes() + 5)
  const validUntil = new Date(signed)
  validUntil.setFullYear(signed.getFullYear() + 30)

  test('correctly instantiate an issuer signed object', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      claims
    )
    issuerSigned = await issuerSignedBuilder.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })
    _issuerSignedEncoded = issuerSigned.encode()

    expect(issuerSigned.issuerNamespaces).toBeDefined()
    expect(issuerSigned.issuerNamespaces?.issuerNamespaces.has('org.iso.18013.5.1')).toBeTruthy()
    expect(issuerSigned.issuerAuth.signature).toBeDefined()

    const verificationResult = await issuerSigned.issuerAuth.verify({}, mdocContext)

    expect(verificationResult).toBeTruthy()
  })

  test('verify issuer signature', async () => {
    await expect(
      issuerSigned.issuerAuth.validate(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.not.toThrow()
  })

  test('verify validity info', async () => {
    const { validityInfo } = issuerSigned.issuerAuth.mobileSecurityObject

    expect(validityInfo).toBeDefined()
    expect(validityInfo.signed).toEqual(signed)
    expect(validityInfo.validFrom).toEqual(validFrom)
    expect(validityInfo.validUntil).toEqual(validUntil)
    expect(validityInfo.expectedUpdate).toBeUndefined()
  })

  test('set correct digest algorithm', () => {
    const { digestAlgorithm } = issuerSigned.issuerAuth.mobileSecurityObject
    expect(digestAlgorithm).toEqual('SHA-256')
  })

  test('set correct device key', () => {
    const { deviceKeyInfo } = issuerSigned.issuerAuth.mobileSecurityObject
    expect(deviceKeyInfo?.deviceKey).toBeDefined()
    expect(deviceKeyInfo.deviceKey.jwk).toEqual(DEVICE_JWK)
  })

  test('should include the namespace and attributes', () => {
    const prettyClaims = issuerSigned.getPrettyClaims('org.iso.18013.5.1')
    expect(prettyClaims).toEqual(claims)
  })
})
