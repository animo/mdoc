import { base64url, hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  DeviceRequest,
  EncryptedResponse,
  EncryptedResponseData,
  EncryptionInfo,
  EncryptionParameters,
  InvalidDcApiRequestError,
  InvalidDcApiResponseError,
  InvalidEncryptionInfoError,
  IsoMdocDcApi,
  MissingOriginError,
  type VerificationAssessment,
} from '../../src'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import {
  createIssuerSigned,
  issuerCertificate,
  mdlDocType,
  mdlNamespace,
  RECIPIENT_JWK_PRIVATE,
  RECIPIENT_JWK_PUBLIC,
} from './fixtures'
import { createReaderCertificate } from './reader-certificate'

const origin = 'https://verifier.example.com'
const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const recipientPublicKey = CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC)
const recipientPrivateKey = CoseKey.fromJwk(RECIPIENT_JWK_PRIVATE)
const trustedCertificates = [{ issuance: [issuerCertificate] }]

const requestedNamespaces = {
  [mdlNamespace]: { family_name: true, given_name: false },
}

async function createRequest() {
  return await IsoMdocDcApi.createRequest(
    {
      docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
      recipientPublicKey,
    },
    mdocContext
  )
}

describe('IsoMdocDcApi round trip', () => {
  test('request → response → decrypt → verify', async () => {
    const issuerSigned = await createIssuerSigned()

    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    expect(parsedRequest.docRequests).toHaveLength(1)
    expect(parsedRequest.docRequests[0].docType).toBe(mdlDocType)
    expect(parsedRequest.docRequests[0].readerAuthenticated).toBe(false)
    expect(parsedRequest.encryptionInfo.nonce).toHaveLength(16)

    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse, verificationResult } = await IsoMdocDcApi.verifyResponse(
      {
        response,
        origin,
        encryptionInfo: request.encryptionInfo,
        recipientKey: recipientPrivateKey,
        deviceRequest: DeviceRequest.decode(base64url.decode(request.deviceRequest)),
        trustedCertificates,
      },
      mdocContext
    )

    expect(verificationResult.documents).toHaveLength(1)
    expect(verificationResult.deviceRequestMatch?.success).toBe(true)
    expect(deviceResponse.documents?.[0].docType).toBe(mdlDocType)

    // Only the requested elements are disclosed.
    const claims = deviceResponse.documents?.[0].issuerSigned.getPrettyClaims(mdlNamespace)
    expect(claims).toStrictEqual({ family_name: 'Doe', given_name: 'John' })
  })

  test('encrypted response carries a raw 65-byte P-256 enc, not a COSE_Key', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const encryptedResponse = EncryptedResponse.fromBase64Url(response)
    expect(encryptedResponse.enc).toHaveLength(65)
    expect(encryptedResponse.enc[0]).toBe(0x04)
  })

  test('a response relayed to a different origin cannot be decrypted', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response,
          origin: 'https://attacker.example.com',
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('parseRequest aborts when the DC API provided no origin (C.5)', async () => {
    const { request } = await createRequest()

    await expect(IsoMdocDcApi.parseRequest({ request, origin: undefined }, mdocContext)).rejects.toThrow(
      MissingOriginError
    )
  })

  test('parseRequest rejects a nonce with less than 16 bytes', async () => {
    const { request } = await createRequest()

    const shortNonce = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({
        nonce: hex.decode('00112233445566778899aabb'),
        recipientPublicKey,
      }),
    })

    await expect(
      IsoMdocDcApi.parseRequest(
        { request: { ...request, encryptionInfo: shortNonce.toBase64Url() }, origin },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('createRequest rejects a nonce with less than 16 bytes', async () => {
    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
          recipientPublicKey,
          nonce: hex.decode('00112233445566778899aabb'),
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('createRequest rejects a recipient key that is not P-256', async () => {
    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
          recipientPublicKey: CoseKey.fromJwk({
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'gCTHOgU_uZLdSTHo-BvNBGXO83SwCajwZAaJT1lhbjw',
          }),
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('verification fails when the ciphertext is tampered with', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const encryptedResponse = EncryptedResponse.fromBase64Url(response)
    const ciphertext = new Uint8Array(encryptedResponse.ciphertext)
    ciphertext[0] ^= 0xff

    const tampered = EncryptedResponse.create({
      encryptedResponseData: EncryptedResponseData.create({ enc: encryptedResponse.enc, ciphertext }),
    })

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response: tampered.toBase64Url(),
          origin,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('createResponse answers a multi-document request', async () => {
    const mdl = await createIssuerSigned()
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const photoId = await createIssuerSigned({ docType: photoIdDocType })

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [
          { docType: mdlDocType, namespaces: requestedNamespaces },
          { docType: photoIdDocType, namespaces: requestedNamespaces },
        ],
        recipientPublicKey,
      },
      mdocContext
    )

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      {
        parsedRequest,
        documents: [
          { issuerSigned: mdl, deviceKey, docRequestIndex: 0 },
          { issuerSigned: photoId, deviceKey, docRequestIndex: 1 },
        ],
      },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents?.map((d) => d.docType)).toStrictEqual([mdlDocType, photoIdDocType])
  })

  test('createResponse may answer only part of a request', async () => {
    const mdl = await createIssuerSigned()
    const photoIdDocType = 'org.iso.23220.photoid.1'

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [
          { docType: mdlDocType, namespaces: requestedNamespaces },
          { docType: photoIdDocType, namespaces: requestedNamespaces },
        ],
        recipientPublicKey,
      },
      mdocContext
    )

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned: mdl, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })

  test('createResponse throws when the context has no HPKE support', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()
    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)

    const contextWithoutHpke = { ...mdocContext, crypto: { ...mdocContext.crypto, hpke: undefined } }

    await expect(
      IsoMdocDcApi.createResponse(
        { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
        contextWithoutHpke
      )
    ).rejects.toThrow('does not provide HPKE support')
  })
})

describe('IsoMdocDcApi reader auth', () => {
  test('a signed request is verified against the transcript of its origin', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    const parsedRequest = await IsoMdocDcApi.parseRequest(
      {
        request,
        origin,
        trustedReaderCertificates: [readerCertificate],
        verificationCallback: (assessment) => checks.push(assessment),
      },
      mdocContext
    )

    expect(parsedRequest.docRequests[0].readerAuthenticated).toBe(true)
    expect(parsedRequest.docRequests[0].readerCertificateChain).toHaveLength(1)
    expect(checks.filter((check) => check.status === 'FAILED')).toStrictEqual([])
  })

  test('a signed request fails verification at a different origin', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    await IsoMdocDcApi.parseRequest(
      {
        request,
        origin: 'https://other.example.com',
        verificationCallback: (assessment) => checks.push(assessment),
      },
      mdocContext
    )

    const signatureCheck = checks.find((check) => check.check.includes('Signature is invalid on the reader auth'))
    expect(signatureCheck?.status).toBe('FAILED')
  })
})

describe('IsoMdocDcApi payload validation', () => {
  test.each([
    ['a missing member', { deviceRequest: 'aGVsbG8' }],
    ['a member that is not a string', { deviceRequest: 'aGVsbG8', encryptionInfo: 42 }],
    ['a member that is not base64url', { deviceRequest: 'aGVsbG8', encryptionInfo: 'not base64url!' }],
    ['a padded member', { deviceRequest: 'aGVsbG8', encryptionInfo: 'aGVsbG8=' }],
    ['a payload that is not an object', 'not-an-object'],
  ])('parseRequest rejects a request with %s', async (_, request) => {
    await expect(
      // biome-ignore lint/suspicious/noExplicitAny: the point is that this is unvalidated input
      IsoMdocDcApi.parseRequest({ request: request as any, origin }, mdocContext)
    ).rejects.toThrow(InvalidDcApiRequestError)
  })

  test('decryptResponse rejects a malformed response', async () => {
    const { request } = await createRequest()

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          // biome-ignore lint/suspicious/noExplicitAny: the point is that this is unvalidated input
          response: { response: 'not base64url!' } as any,
          origin,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidDcApiResponseError)
  })

  test('decryptResponse accepts the response as a bare string', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()
    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })
})
