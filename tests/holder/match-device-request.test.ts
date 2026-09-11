import { assert, describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedItems,
  DocRequest,
  Holder,
  ItemsRequest,
  KeyAuthorizations,
  MissingRequestedElementError,
  SessionTranscript,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const sessionTranscript = SessionTranscript.create({ handover: NullHandover.fromEncodedStructure(null) })

const photoIdDocType = 'org.iso.23220.photoid.1'
const deviceNamespace = 'com.example.device'

const createDeviceRequest = (
  docRequests: Array<{ docType?: string; namespaces: Record<string, Record<string, boolean>> }>
) =>
  DeviceRequest.create({
    docRequests: docRequests.map(({ docType, namespaces }) =>
      DocRequest.create({ itemsRequest: ItemsRequest.create({ docType: docType ?? mdlDocType, namespaces }) })
    ),
  })

const deviceNamespaces = (values: Record<string, Record<string, unknown>>) =>
  DeviceNamespaces.create({
    deviceNamespaces: new Map(
      Object.entries(values).map(([namespace, elements]) => [
        namespace,
        DeviceSignedItems.create({ deviceSignedItems: new Map(Object.entries(elements)) }),
      ])
    ),
  })

describe('Holder.matchDeviceRequest', () => {
  test('a credential containing every requested element matches in full', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false } } },
    ])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ docType: photoIdDocType }), await createIssuerSigned()],
    })

    expect(match.success).toBe(true)

    const [docRequest] = match.docRequests
    expect(docRequest).toMatchObject({ docRequestIndex: 0, docType: mdlDocType, success: true })
    expect(docRequest.validCredentials).toStrictEqual([
      {
        credentialIndex: 1,
        success: true,
        docType: { success: true, docType: mdlDocType },
        claims: {
          success: true,
          validClaims: [
            {
              success: true,
              namespace: mdlNamespace,
              elementIdentifier: 'family_name',
              intentToRetain: true,
              optional: false,
              disclosedElementIdentifier: 'family_name',
              elementValue: 'Doe',
              source: 'issuerSigned',
            },
            {
              success: true,
              namespace: mdlNamespace,
              elementIdentifier: 'given_name',
              intentToRetain: false,
              optional: false,
              disclosedElementIdentifier: 'given_name',
              elementValue: 'John',
              source: 'issuerSigned',
            },
          ],
          failedClaims: [],
        },
      },
    ])

    // The credential of another docType fails on its docType.
    expect(docRequest.failedCredentials).toHaveLength(1)
    expect(docRequest.failedCredentials[0]).toMatchObject({
      credentialIndex: 0,
      success: false,
      docType: {
        success: false,
        docType: photoIdDocType,
        reason: `Credential has docType '${photoIdDocType}', but docType '${mdlDocType}' was requested`,
      },
    })
  })

  test('a credential of the requested docType reports the claims it is missing', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    const match = Holder.matchDeviceRequest({ deviceRequest, credentials: [await createIssuerSigned()] })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].validCredentials).toStrictEqual([])

    // "You have this credential, but these claims are missing"
    const [credentialMatch] = match.docRequests[0].failedCredentials
    expect(credentialMatch).toMatchObject({ success: false, docType: { success: true }, claims: { success: false } })
    expect(credentialMatch.claims.validClaims.map((claim) => claim.elementIdentifier)).toStrictEqual(['family_name'])
    expect(credentialMatch.claims.failedClaims).toStrictEqual([
      {
        success: false,
        namespace: mdlNamespace,
        elementIdentifier: 'portrait',
        intentToRetain: true,
        optional: false,
        failure: 'notDisclosed',
        reason: `Element 'portrait' in namespace '${mdlNamespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
      },
    ])
  })

  test('an age_over_NN request is answered by the age attestation 18013-5 7.2.5 allows', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ claims: { age_over_21: true } })],
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[0]).toMatchObject({
      success: true,
      elementIdentifier: 'age_over_18',
      disclosedElementIdentifier: 'age_over_21',
      elementValue: true,
    })
  })

  test('an element that is not issuer-signed but the device key is authorized for is disclosed device-signed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        await createIssuerSigned({ keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }) }),
      ],
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[1]).toStrictEqual({
      success: true,
      namespace: deviceNamespace,
      elementIdentifier: 'session_id',
      intentToRetain: false,
      optional: false,
      disclosedElementIdentifier: 'session_id',
      elementValue: undefined,
      source: 'deviceSigned',
    })
  })

  test('an issuer-signed element is disclosed issuer-signed, also when the device key is authorized for it', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        await createIssuerSigned({ keyAuthorizations: KeyAuthorizations.create({ namespaces: [mdlNamespace] }) }),
      ],
    })

    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[0]).toMatchObject({
      source: 'issuerSigned',
      elementValue: 'Doe',
    })
  })
})

describe('creating a response from a holder match', () => {
  test('a response for a credential that matched in full satisfies the verifier match', async () => {
    const deviceRequest = createDeviceRequest([
      {
        namespaces: {
          [mdlNamespace]: { family_name: true, age_over_18: true },
          [deviceNamespace]: { session_id: false },
        },
      },
    ])
    const issuerSigned = await createIssuerSigned({
      claims: { age_over_21: true },
      keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
    })

    const holderMatch = Holder.matchDeviceRequest({ deviceRequest, credentials: [issuerSigned] })
    expect(holderMatch.success).toBe(true)

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned,
            docRequestIndex: 0,
            deviceNamespaces: deviceNamespaces({ [deviceNamespace]: { session_id: 'abc' } }),
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const verifierMatch = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [deviceNamespace]: { '*': { source: 'deviceSigned' } } } }],
      },
    })

    expect(verifierMatch.success).toBe(true)
    const [verifierDocRequest] = verifierMatch.docRequests
    assert(verifierDocRequest.success)
    const [document] = verifierDocRequest.validDocuments
    expect(document.claims.unrequestedClaims).toStrictEqual([])

    // Both sides report the same claims, except that the holder does not know the device-signed value.
    const [holderDocRequest] = holderMatch.docRequests
    assert(holderDocRequest.success)
    const holderClaims = holderDocRequest.validCredentials[0].claims.validClaims
    expect(document.claims.validClaims).toStrictEqual(
      holderClaims.map((claim) => (claim.source === 'deviceSigned' ? { ...claim, elementValue: 'abc' } : claim))
    )
  })

  test('a device-signed element needs a value in the device namespaces', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [deviceNamespace]: { session_id: false } } }])
    const issuerSigned = await createIssuerSigned({
      keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
    })

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new MissingRequestedElementError(
        `Element 'session_id' in namespace '${deviceNamespace}' is not issuer-signed in the credential, so it has to be disclosed device-signed, but no value was provided for it in the device namespaces`
      )
    )
  })

  test('a requested element that is neither issuer-signed nor authorized cannot be disclosed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(MissingRequestedElementError)
  })

  test('elements selects which requested elements are disclosed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false, portrait: true } } },
    ])

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 0,
            elements: { [mdlNamespace]: ['family_name'] },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [
          {
            docRequestIndex: 0,
            elements: { [mdlNamespace]: { given_name: { optional: true }, portrait: { optional: true } } },
          },
        ],
      },
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    const { claims } = docRequest.validDocuments[0]
    expect(claims.validClaims.map((claim) => claim.elementIdentifier)).toEqual(['family_name'])
    expect(claims.failedClaims.map((claim) => claim.elementIdentifier)).toEqual(['given_name', 'portrait'])
  })

  test('an element that is not requested cannot be selected', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned(),
              docRequestIndex: 0,
              elements: { [mdlNamespace]: ['family_name', 'birth_date'] },
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(`Element 'birth_date' in namespace '${mdlNamespace}' is selected for disclosure`)
  })
})
