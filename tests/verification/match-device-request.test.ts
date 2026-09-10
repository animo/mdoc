import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  type ClaimMatchFailure,
  type ClaimMatchSuccess,
  CoseKey,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedItems,
  DocRequest,
  Document,
  DocumentError,
  type IssuerSigned,
  ItemsRequest,
  KeyAuthorizations,
  SessionTranscript,
  type VerificationAssessment,
  VerificationError,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const sessionTranscript = SessionTranscript.create({ handover: NullHandover.fromEncodedStructure(null) })

const createDeviceRequest = (
  docRequests: Array<{ docType?: string; namespaces: Record<string, Record<string, boolean>> }>
) =>
  DeviceRequest.create({
    docRequests: docRequests.map(({ docType, namespaces }) =>
      DocRequest.create({ itemsRequest: ItemsRequest.create({ docType: docType ?? mdlDocType, namespaces }) })
    ),
  })

/**
 * Build a response for `disclosedRequest` — the request the mdoc answered — so it can be matched
 * against a different request to model a partial or over-disclosing response.
 */
const createDeviceResponse = async (options: {
  deviceRequest: DeviceRequest
  issuerSigned: Array<IssuerSigned>
  deviceNamespaces?: DeviceNamespaces
}) =>
  await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest: options.deviceRequest,
      sessionTranscript,
      documents: options.issuerSigned.map((issuerSigned, docRequestIndex) => ({
        issuerSigned,
        docRequestIndex,
        deviceNamespaces: options.deviceNamespaces,
        signature: { signingKey: deviceKey },
      })),
    },
    mdocContext
  )

describe('matchDeviceRequest', () => {
  test('a response disclosing every requested element satisfies the request', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false } } },
    ])
    const deviceResponse = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.unrequestedDocuments).toHaveLength(0)
    expect(match.docRequests).toHaveLength(1)

    const [docRequest] = match.docRequests
    expect(docRequest).toMatchObject({ docRequestIndex: 0, docType: mdlDocType, success: true })
    expect(docRequest.documents).toHaveLength(1)

    const [document] = docRequest.documents
    expect(document).toMatchObject({ documentIndex: 0, success: true, unrequestedClaims: [] })
    expect(document.claims).toStrictEqual([
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
    ])
  })

  test('an element the mdoc withheld is reported per claim, not as a missing document', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)

    const [document] = match.docRequests[0].documents
    expect(document.success).toBe(false)
    expect(document.claims.map((claim) => [claim.elementIdentifier, claim.success])).toStrictEqual([
      ['family_name', true],
      ['birth_date', false],
    ])
    expect((document.claims[1] as ClaimMatchFailure).reason).toContain('birth_date')
  })

  test('elements the mdoc disclosed but the request did not ask for are reported as unrequested', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    // Over-disclosure does not make the request unsatisfied — it is reported separately.
    expect(match.success).toBe(true)
    expect(match.docRequests[0].documents[0].unrequestedClaims).toStrictEqual([
      { namespace: mdlNamespace, elementIdentifier: 'birth_date', elementValue: '1990-01-01', source: 'issuerSigned' },
    ])
  })

  test('a doc request answered by no document reports the docType and the document error code', async () => {
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: true } } },
    ])

    const disclosed = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const deviceResponse = DeviceResponse.createSimple({
      documents: disclosed.documents,
      documentErrors: [DocumentError.create({ documentError: new Map([[photoIdDocType, 0]]) })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].success).toBe(true)
    expect(match.docRequests[1]).toMatchObject({
      docRequestIndex: 1,
      docType: photoIdDocType,
      success: false,
      documents: [],
    })
    expect(match.docRequests[1].reason).toContain(photoIdDocType)
  })

  test('an age_over_NN request is satisfied by a different age attestation (18013-5 7.2.5)', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_21: true } } }])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned({ claims: { age_over_21: true } })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    const claim = match.docRequests[0].documents[0].claims[0] as ClaimMatchSuccess
    expect(claim).toMatchObject({
      success: true,
      elementIdentifier: 'age_over_18',
      disclosedElementIdentifier: 'age_over_21',
      elementValue: true,
    })
    // The substituted attestation answers the request, so it is not over-disclosure.
    expect(match.docRequests[0].documents[0].unrequestedClaims).toHaveLength(0)
  })

  /**
   * An MSO that authorizes the device key to self-assert an age attestation in the mDL namespace.
   * The mdoc cannot build such a response without it (9.1.3.4), and the verifier should still not
   * accept the result as an answer to a request for an issuer-signed attestation.
   */
  const ageOverKeyAuthorizations = KeyAuthorizations.create({
    dataElements: new Map([[mdlNamespace, ['age_over_21']]]),
  })

  test('a device-signed element only matches when the verifier marked it as device-signed', async () => {
    const deviceNamespace = 'com.example.device'
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [
        await createIssuerSigned({
          keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
        }),
      ],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [deviceNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['session_id', 'abc']]) })],
        ]),
      }),
    })

    // Without the element options the device-signed element does not answer the request.
    const withoutOptions = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    expect(withoutOptions.success).toBe(false)
    expect(withoutOptions.docRequests[0].documents[0].claims[1]).toMatchObject({
      success: false,
      failure: 'disallowedSource',
      disclosedFrom: 'deviceSigned',
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      elements: { [mdlDocType]: { [deviceNamespace]: { '*': { source: 'deviceSigned' } } } },
    })

    expect(match.success).toBe(true)
    const claim = match.docRequests[0].documents[0].claims[1] as ClaimMatchSuccess
    expect(claim).toMatchObject({
      success: true,
      namespace: deviceNamespace,
      elementIdentifier: 'session_id',
      elementValue: 'abc',
      source: 'deviceSigned',
    })
  })

  test('a device-signed age attestation does not answer a request for an issuer-signed one', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    // An mdoc that self-asserts age_over_21 in the namespace the issuer signs. The MSO authorizes
    // the device key for it, which 18013-5 9.1.3.4 allows but 7.2.1 does not — every Table 5
    // element "shall be returned as part of the IssuerSignedItems".
    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned({ keyAuthorizations: ageOverKeyAuthorizations })],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [mdlNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['age_over_21', true]]) })],
        ]),
      }),
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    const claim = match.docRequests[0].documents[0].claims[0] as ClaimMatchFailure
    expect(claim).toMatchObject({
      success: false,
      elementIdentifier: 'age_over_18',
      failure: 'disallowedSource',
      disclosedFrom: 'deviceSigned',
    })
    expect(claim.reason).toContain('must be disclosed through issuerSigned')
  })

  test('an issuer-signed element still answers the request when a device-signed one is also present', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [
        await createIssuerSigned({
          claims: { age_over_18: true },
          keyAuthorizations: ageOverKeyAuthorizations,
        }),
      ],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [mdlNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['age_over_21', true]]) })],
        ]),
      }),
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.docRequests[0].documents[0].claims[0]).toMatchObject({
      success: true,
      disclosedElementIdentifier: 'age_over_18',
      source: 'issuerSigned',
    })
    // The self-asserted attestation was not requested from deviceSigned.
    expect(match.docRequests[0].documents[0].unrequestedClaims).toStrictEqual([
      { namespace: mdlNamespace, elementIdentifier: 'age_over_21', elementValue: true, source: 'deviceSigned' },
    ])
  })

  test('an optional element the mdoc withheld does not fail the match', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: false } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      elements: { [mdlDocType]: { [mdlNamespace]: { portrait: { optional: true } } } },
    })

    expect(match.success).toBe(true)
    // The absence is still reported per claim, it just does not make the document fail.
    expect(match.docRequests[0].documents[0].claims[1]).toMatchObject({
      success: false,
      elementIdentifier: 'portrait',
      optional: true,
      failure: 'notDisclosed',
    })
  })

  test('a document whose MSO docType differs from its docType does not answer the doc request', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { docType: 'org.iso.23220.photoid.1', namespaces: { [mdlNamespace]: { family_name: true } } },
    ])

    const disclosed = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })
    const [document] = disclosed.documents ?? []

    // The docType outside the MSO is not signed, so an mdoc can claim any docType for a document
    // the issuer attested to under a different one.
    const deviceResponse = DeviceResponse.createSimple({
      documents: [
        Document.create({
          docType: 'org.iso.23220.photoid.1',
          issuerSigned: document.issuerSigned,
          deviceSigned: document.deviceSigned,
        }),
      ],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].documents[0].reason).toContain(mdlDocType)
  })

  test('documents the device request did not ask for are reported', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { docType: 'org.iso.23220.photoid.1', namespaces: { [mdlNamespace]: { family_name: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned(), await createIssuerSigned({ docType: 'org.iso.23220.photoid.1' })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.unrequestedDocuments).toHaveLength(1)
    expect(match.unrequestedDocuments[0]).toMatchObject({ documentIndex: 1, docType: 'org.iso.23220.photoid.1' })
  })

  test('accepts encoded device requests and responses', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest: deviceRequest.encode(),
      deviceResponse: deviceResponse.encode(),
    })

    expect(match.success).toBe(true)
  })
})

describe('DeviceResponse.verify with a device request', () => {
  const trustedCertificates: Array<{ issuance: Uint8Array[] }> = []

  test('an unsatisfied doc request is a FAILED check', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const checks: Array<VerificationAssessment> = []
    const { deviceRequestMatch } = await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    const check = checks.find((c) => c.check.startsWith('Device response must satisfy doc request 0'))
    expect(check?.status).toBe('FAILED')
    expect(check?.reason).toContain('birth_date')

    // A collecting callback does not throw, so the match is returned instead.
    expect(deviceRequestMatch?.success).toBe(false)
    expect(deviceRequestMatch?.docRequests[0].documents[0].claims.find((claim) => !claim.success)).toMatchObject({
      elementIdentifier: 'birth_date',
      failure: 'notDisclosed',
    })
  })

  test('over-disclosure is a WARNING, not a failure', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const checks: Array<VerificationAssessment> = []
    await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(checks.find((c) => c.check.startsWith('Device response must satisfy doc request 0'))?.status).toBe('PASSED')

    const warning = checks.find((c) => c.check.includes('must not disclose elements that were not requested'))
    expect(warning?.status).toBe('WARNING')
    expect(warning?.reason).toContain('birth_date')
  })

  test('the default verification callback throws a VerificationError carrying the match', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    // The other tests collect the checks, so this one has to actually pass issuer auth to reach
    // the doc request check that the default callback throws on.
    const error = await deviceResponse
      .verify(
        {
          deviceRequest,
          sessionTranscript,
          trustedCertificates: [{ issuance: [issuerCertificate] }],
        },
        mdocContext
      )
      .then(
        () => undefined,
        (error) => error
      )

    expect(error).toBeInstanceOf(VerificationError)
    const { assessment } = error as VerificationError
    expect(assessment.status).toBe('FAILED')
    expect(assessment.check).toContain('doc request 0')

    // The structured match survives the throw, so a caller that does not collect the checks itself
    // can still see which claim failed and why.
    expect(assessment.result?.type).toBe('deviceRequestMatch')
    const match = assessment.result?.match
    expect(match?.success).toBe(false)
    expect(match?.docRequests[0].documents[0].claims.filter((claim) => !claim.success)).toEqual([
      expect.objectContaining({ elementIdentifier: 'birth_date', failure: 'notDisclosed' }),
    ])
  })
})
