import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  DeviceKeyNotAuthorizedError,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedItems,
  DocRequest,
  Document,
  IssuerNamespaces,
  IssuerSigned,
  ItemsRequest,
  KeyAuthorizations,
  SessionTranscript,
  type VerificationAssessment,
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
const deviceNamespace = 'com.example.device'

const familyNameRequest = DeviceRequest.create({
  docRequests: [
    DocRequest.create({
      itemsRequest: ItemsRequest.create({ docType: mdlDocType, namespaces: { [mdlNamespace]: { family_name: true } } }),
    }),
  ],
})

const createDeviceResponse = async (options: { issuerSigned: IssuerSigned; deviceNamespaces?: DeviceNamespaces }) =>
  await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest: familyNameRequest,
      sessionTranscript,
      documents: [
        {
          issuerSigned: options.issuerSigned,
          docRequestIndex: 0,
          deviceNamespaces: options.deviceNamespaces,
          signature: { signingKey: deviceKey },
        },
      ],
    },
    mdocContext
  )

/**
 * Run verification without throwing on a FAILED check, so every emitted check can be asserted on.
 */
const collectChecks = async (deviceResponse: DeviceResponse) => {
  const checks: Array<VerificationAssessment> = []
  await deviceResponse.verify(
    {
      sessionTranscript,
      trustedCertificates: [],
      disableCertificateChainValidation: true,
      onCheck: (check) => checks.push(check),
    },
    mdocContext
  )
  return checks
}

const sessionIdNamespaces = DeviceNamespaces.create({
  deviceNamespaces: new Map([
    [deviceNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['session_id', 'abc']]) })],
  ]),
})

const keyAuthorizationsCheck =
  'Device signed elements must be authorized by the key authorizations in the mobile security object'

/**
 * Assemble a response whose device-signed elements the MSO does not authorize the device key for.
 * `createWithDeviceRequest` refuses to build one — 18013-5 9.1.3.4 binds the mdoc as well as the
 * mdoc reader — so the unauthorized issuer-signed data is swapped in afterwards, the way a
 * non-conformant mdoc would produce it. Device auth stays valid, as it covers the device namespaces
 * and not the MSO.
 */
const createUnauthorizedDeviceResponse = async (issuerSigned: IssuerSigned) => {
  const authorized = await createDeviceResponse({
    issuerSigned: await createIssuerSigned({
      keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
    }),
    deviceNamespaces: sessionIdNamespaces,
  })
  const [document] = authorized.documents ?? []

  return DeviceResponse.createSimple({
    documents: [Document.create({ docType: document.docType, issuerSigned, deviceSigned: document.deviceSigned })],
  })
}

describe('key authorizations (18013-5 9.1.3.4)', () => {
  test('device signed elements without any key authorizations FAIL', async () => {
    const deviceResponse = await createUnauthorizedDeviceResponse(await createIssuerSigned())

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === keyAuthorizationsCheck)
    expect(check?.status).toBe('FAILED')
    expect(check?.reason).toContain('session_id')
  })

  test('a whole authorized namespace PASSES', async () => {
    const deviceResponse = await createDeviceResponse({
      issuerSigned: await createIssuerSigned({
        keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
      }),
      deviceNamespaces: sessionIdNamespaces,
    })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === keyAuthorizationsCheck)
    expect(check?.status).toBe('PASSED')
  })

  test('a per-element authorization PASSES', async () => {
    const deviceResponse = await createDeviceResponse({
      issuerSigned: await createIssuerSigned({
        keyAuthorizations: KeyAuthorizations.create({
          dataElements: new Map([[deviceNamespace, ['session_id']]]),
        }),
      }),
      deviceNamespaces: sessionIdNamespaces,
    })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === keyAuthorizationsCheck)
    expect(check?.status).toBe('PASSED')
  })

  test('an authorization for a different element FAILS', async () => {
    const deviceResponse = await createUnauthorizedDeviceResponse(
      await createIssuerSigned({
        keyAuthorizations: KeyAuthorizations.create({
          dataElements: new Map([[deviceNamespace, ['transaction_id']]]),
        }),
      })
    )

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === keyAuthorizationsCheck)
    expect(check?.status).toBe('FAILED')
  })

  test('empty device namespaces emit no key authorization check', async () => {
    const deviceResponse = await createDeviceResponse({ issuerSigned: await createIssuerSigned() })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === keyAuthorizationsCheck)
    expect(check).toBeUndefined()
  })

  test('creating a response with unauthorized device signed elements throws', async () => {
    await expect(
      createDeviceResponse({ issuerSigned: await createIssuerSigned(), deviceNamespaces: sessionIdNamespaces })
    ).rejects.toThrow(DeviceKeyNotAuthorizedError)
  })

  test('creating a response with authorized device signed elements succeeds', async () => {
    const deviceResponse = await createDeviceResponse({
      issuerSigned: await createIssuerSigned({
        keyAuthorizations: KeyAuthorizations.create({ dataElements: new Map([[deviceNamespace, ['session_id']]]) }),
      }),
      deviceNamespaces: sessionIdNamespaces,
    })

    expect(deviceResponse.documents).toHaveLength(1)
  })
})

describe('response status (18013-5 8.3.2.1.2.3, Table 8)', () => {
  const statusCheck = 'Device Response must not include documents when the status is not 0.'

  test('a non-zero status with documents FAILS', async () => {
    const disclosed = await createDeviceResponse({ issuerSigned: await createIssuerSigned() })
    const deviceResponse = DeviceResponse.createSimple({ documents: disclosed.documents, status: 10 })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === statusCheck)
    expect(check?.status).toBe('FAILED')
    expect(check?.reason).toContain('status 10')
  })

  test('a non-zero status without documents PASSES', async () => {
    const deviceResponse = DeviceResponse.createSimple({ status: 10 })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === statusCheck)
    expect(check?.status).toBe('PASSED')
  })

  test('status 0 with documents PASSES', async () => {
    const deviceResponse = await createDeviceResponse({ issuerSigned: await createIssuerSigned() })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === statusCheck)
    expect(check?.status).toBe('PASSED')
  })
})

describe('duplicate element identifiers (18013-5 8.3.2.1.2.2)', () => {
  const duplicateCheck = `Namespace ${mdlNamespace} must not include multiple elements with the same element identifier`

  test('two items with the same element identifier in one namespace FAIL', async () => {
    const issuerSigned = await createIssuerSigned()
    const items = issuerSigned.getIssuerNamespace(mdlNamespace) ?? []
    const familyName = items.find((item) => item.elementIdentifier === 'family_name')
    expect(familyName).toBeDefined()

    // Built directly rather than through createWithDeviceRequest, whose limit-disclosure step
    // rebuilds the namespaces from the request and would drop the duplicate.
    const disclosed = await createDeviceResponse({ issuerSigned })
    const [document] = disclosed.documents ?? []

    const deviceResponse = DeviceResponse.createSimple({
      documents: [
        Document.create({
          docType: document.docType,
          deviceSigned: document.deviceSigned,
          issuerSigned: IssuerSigned.create({
            issuerAuth: issuerSigned.issuerAuth,
            // The same item twice: each digest still matches, isolating the duplicate check.
            issuerNamespaces: IssuerNamespaces.create({
              issuerNamespaces: new Map([
                [mdlNamespace, [familyName as (typeof items)[number], familyName as (typeof items)[number]]],
              ]),
            }),
          }),
        }),
      ],
    })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === duplicateCheck)
    expect(check?.status).toBe('FAILED')
    expect(check?.reason).toContain('family_name')
  })

  test('distinct element identifiers PASS', async () => {
    const deviceResponse = await createDeviceResponse({ issuerSigned: await createIssuerSigned() })

    const check = (await collectChecks(deviceResponse)).find((c) => c.check === duplicateCheck)
    expect(check?.status).toBe('PASSED')
  })
})
