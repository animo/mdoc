import { X509Certificate } from '@peculiar/x509'
import { expect, suite, test } from 'vitest'
import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  Holder,
  Issuer,
  IssuerSigned,
  ItemsRequest,
  SessionTranscript,
  SignatureAlgorithm,
  Verifier,
} from '../../src'
import { mdocContext } from '../context'
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

suite('Verification', () => {
  test('Verify simple mdoc', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    const deviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        verifierGeneratedNonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse: decodedDeviceResponse,
        sessionTranscript: fakeSessionTranscript,
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      },
      mdocContext
    )
  })

  test('Verify mdoc with selective disclosure', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      middle_name: 'Middle',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    const deviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        verifierGeneratedNonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK) },
      },
      mdocContext
    )

    expect(deviceResponse.documents?.[0].issuerSigned.getPrettyClaims('org.iso.18013.5.1.mDL')).toMatchObject({
      first_name: 'First',
      last_name: 'Last',
    })

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    await expect(
      Verifier.verifyDeviceResponse(
        {
          deviceRequest,
          deviceResponse: decodedDeviceResponse,
          sessionTranscript: fakeSessionTranscript,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })

  test('Fail to create mdoc with not enough attributes', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    const deviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                middle_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        verifierGeneratedNonce: 'my-random-nonce',
      },
      mdocContext
    )

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          issuerSigned: [credential],
          sessionTranscript: fakeSessionTranscript,
          signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK) },
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('Fail to verify with not matching device request', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificate: new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: CoseKey.fromJwk(DEVICE_JWK) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    const deviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        verifierGeneratedNonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    const newDeviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                middle_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    await expect(
      Verifier.verifyDeviceResponse(
        {
          deviceRequest: newDeviceRequest,
          deviceResponse: decodedDeviceResponse,
          sessionTranscript: fakeSessionTranscript,
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).rejects.toThrow()
  })
})
