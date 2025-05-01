import { randomFillSync } from 'node:crypto'
import { X509Certificate } from '@peculiar/x509'
import { beforeAll, describe, expect, it } from 'vitest'
import type { DeviceSignedDocument } from '../../src'
import {
  DataItem,
  DeviceResponseOld,
  Document,
  MDoc,
  Verifier,
  cborDecode,
  cborEncode,
  parseDeviceResponse,
} from '../../src'
import { mdocContext } from '../context'
import {
  DEVICE_JWK,
  ISSUER_CERTIFICATE,
  ISSUER_PRIVATE_KEY_JWK,
  PRESENTATION_DEFINITION_1,
  deviceRequest,
} from './config.js'
const { d, ...publicKeyJWK } = DEVICE_JWK

describe.skip('issuing a device response', () => {
  let encodedDeviceResponse: Uint8Array
  let parsedDocument: DeviceSignedDocument
  let mdoc: MDoc

  const signed = new Date('2023-10-24T14:55:18Z')
  const validUntil = new Date(signed)
  validUntil.setFullYear(signed.getFullYear() + 30)

  beforeAll(async () => {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK

    // this is the ISSUER side
    {
      const document = await new Document('org.iso.18013.5.1.mDL', mdocContext)
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Jones',
          given_name: 'Ava',
          birth_date: '2007-03-25',
          issue_date: '2023-09-01',
          expiry_date: '2028-09-30',
          issuing_country: 'US',
          issuing_authority: 'NY DMV',
          document_number: '01-856-5050',
          portrait: 'bstr',
          driving_privileges: [
            {
              vehicle_category_code: 'C',
              issue_date: '2022-09-02',
              expiry_date: '2027-09-20',
            },
          ],
          un_distinguishing_sign: 'tbd-us.ny.dmv',

          sex: 'F',
          height: '5\' 8"',
          weight: '120lb',
          eye_colour: 'brown',
          hair_colour: 'brown',
          resident_addres: '123 Street Rd',
          resident_city: 'Brooklyn',
          resident_state: 'NY',
          resident_postal_code: '19001',
          resident_country: 'US',
          issuing_jurisdiction: 'New York',
        })
        .useDigestAlgorithm('SHA-512')
        .addValidityInfo({ signed, validUntil })
        .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
        .sign(
          {
            issuerPrivateKey,
            issuerCertificate: ISSUER_CERTIFICATE,
            alg: 'ES256',
          },
          mdocContext
        )

      mdoc = new MDoc([document])
    }
  })

  describe('using OID4VP handover', () => {
    const verifierGeneratedNonce = 'abcdefg'
    const mdocGeneratedNonce = '123456'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback'

    beforeAll(async () => {
      //  This is the Device side
      const devicePrivateKey = DEVICE_JWK
      const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
        .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
        .usingSessionTranscriptForOID4VP({
          mdocGeneratedNonce,
          clientId,
          responseUri,
          verifierGeneratedNonce,
        })
        .authenticateWithSignature(devicePrivateKey, 'ES256')
        .addDeviceNameSpace('com.foobar-device', { test: 1234 })
        .sign(mdocContext)

      encodedDeviceResponse = deviceResponseMDoc.encode()
      const parsedMDOC = parseDeviceResponse(encodedDeviceResponse)
      ;[parsedDocument] = parsedMDOC.documents as [DeviceSignedDocument, ...DeviceSignedDocument[]]
    })

    it('should be verifiable', async () => {
      const verifier = new Verifier()
      await verifier.verifyDeviceResponse(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          encodedDeviceResponse,
          encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({
            context: mdocContext,
            clientId,
            responseUri,
            verifierGeneratedNonce,
            mdocGeneratedNonce,
          }),
        },
        mdocContext
      )
    })

    describe('should not be verifiable', () => {
      const testCases = ['clientId', 'responseUri', 'verifierGeneratedNonce', 'mdocGeneratedNonce']

      testCases.forEach((name) => {
        const values = {
          clientId,
          responseUri,
          verifierGeneratedNonce,
          mdocGeneratedNonce,
          [name]: 'wrong',
        }
        it(`with a different ${name}`, async () => {
          try {
            const verifier = new Verifier()
            await verifier.verifyDeviceResponse(
              {
                trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
                encodedDeviceResponse,
                encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({
                  context: mdocContext,
                  clientId: values.clientId,
                  responseUri: values.responseUri,
                  verifierGeneratedNonce: values.verifierGeneratedNonce,
                  mdocGeneratedNonce: values.mdocGeneratedNonce,
                }),
              },
              mdocContext
            )
            throw new Error('should not validate with different transcripts')
          } catch (error) {
            expect((error as Error).message).toMatch(
              'Unable to verify deviceAuth signature (ECDSA/EdDSA): Device signature must be valid'
            )
          }
        })
      })
    })

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.mobileSecurityObject
      expect(validityInfo).toBeDefined()
      expect(validityInfo.signed).toEqual(signed)
      expect(validityInfo.validFrom).toEqual(signed)
      expect(validityInfo.validUntil).toEqual(validUntil)
      expect(validityInfo.expectedUpdate).toBeUndefined()
    })

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device')).toEqual(new Map([['test', 1234]]))
    })

    it('should generate the signature without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceSignature?.payload).toBeNull()
    })
  })

  describe('DIF Presentation Exchange optional fields', () => {
    const verifierGeneratedNonce = 'abcdefg'
    const mdocGeneratedNonce = '123456'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback'

    it('ignores optional field that is not present', async () => {
      await expect(
        DeviceResponseOld.from(mdoc)
          .usingPresentationDefinition({
            ...PRESENTATION_DEFINITION_1,
            input_descriptors: [
              {
                ...PRESENTATION_DEFINITION_1.input_descriptors[0],
                constraints: {
                  ...PRESENTATION_DEFINITION_1.input_descriptors[0].constraints,
                  fields: [
                    ...PRESENTATION_DEFINITION_1.input_descriptors[0].constraints.fields,
                    {
                      intent_to_retain: true,
                      path: ["$['org.iso.18013.5.1']['non_existent']"],
                      optional: true,
                    },
                  ],
                },
              },
            ],
          })
          .usingSessionTranscriptForOID4VP({
            mdocGeneratedNonce,
            clientId,
            responseUri,
            verifierGeneratedNonce,
          })
          .authenticateWithSignature(DEVICE_JWK, 'ES256')
          .addDeviceNameSpace('com.foobar-device', { test: 1234 })
          .sign(mdocContext)
      ).resolves.not.toThrow()
    })

    it('throws error for non-optional field that is not present', async () => {
      await expect(
        DeviceResponseOld.from(mdoc)
          .usingPresentationDefinition({
            ...PRESENTATION_DEFINITION_1,
            input_descriptors: [
              {
                ...PRESENTATION_DEFINITION_1.input_descriptors[0],
                constraints: {
                  ...PRESENTATION_DEFINITION_1.input_descriptors[0].constraints,
                  fields: [
                    ...PRESENTATION_DEFINITION_1.input_descriptors[0].constraints.fields,
                    {
                      intent_to_retain: true,
                      path: ["$['org.iso.18013.5.1']['non_existent']"],
                    },
                  ],
                },
              },
            ],
          })
          .usingSessionTranscriptForOID4VP({
            mdocGeneratedNonce,
            clientId,
            responseUri,
            verifierGeneratedNonce,
          })
          .authenticateWithSignature(DEVICE_JWK, 'ES256')
          .addDeviceNameSpace('com.foobar-device', { test: 1234 })
          .sign(mdocContext)
      ).rejects.toThrow(
        `Cannot limit the disclosure to the input descriptor. No matching field found for '$['org.iso.18013.5.1']['non_existent']'`
      )
    })
  })

  describe('using OID4VPDCAPI handover', () => {
    const verifierGeneratedNonce = 'abcdefg'
    const origin = 'http://localhost:4000'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'

    beforeAll(async () => {
      //  This is the Device side
      const devicePrivateKey = DEVICE_JWK
      const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
        .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
        .usingSessionTranscriptForForOID4VPDCApi({
          clientId,
          origin,
          verifierGeneratedNonce,
        })
        .authenticateWithSignature(devicePrivateKey, 'ES256')
        .addDeviceNameSpace('com.foobar-device', { test: 1234 })
        .sign(mdocContext)

      encodedDeviceResponse = deviceResponseMDoc.encode()
      const parsedMDOC = parseDeviceResponse(encodedDeviceResponse)
      ;[parsedDocument] = parsedMDOC.documents as [DeviceSignedDocument, ...DeviceSignedDocument[]]
    })

    it('should be verifiable', async () => {
      const verifier = new Verifier()
      await verifier.verifyDeviceResponse(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          encodedDeviceResponse,
          encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VPDCApi({
            context: mdocContext,
            clientId,
            origin,
            verifierGeneratedNonce,
          }),
        },
        mdocContext
      )
    })

    describe('should not be verifiable', () => {
      const testCases = ['clientId', 'origin', 'verifierGeneratedNonce']

      testCases.forEach((name) => {
        const values = {
          clientId,
          origin,
          verifierGeneratedNonce,
          [name]: 'wrong',
        }
        it(`with a different ${name}`, async () => {
          try {
            const verifier = new Verifier()
            await verifier.verifyDeviceResponse(
              {
                trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
                encodedDeviceResponse,
                encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VPDCApi({
                  context: mdocContext,
                  clientId: values.clientId,
                  origin: values.origin,
                  verifierGeneratedNonce: values.verifierGeneratedNonce,
                }),
              },
              mdocContext
            )
            throw new Error('should not validate with different transcripts')
          } catch (error) {
            expect((error as Error).message).toMatch(
              'Unable to verify deviceAuth signature (ECDSA/EdDSA): Device signature must be valid'
            )
          }
        })
      })
    })

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.mobileSecurityObject
      expect(validityInfo).toBeDefined()
      expect(validityInfo.signed).toEqual(signed)
      expect(validityInfo.validFrom).toEqual(signed)
      expect(validityInfo.validUntil).toEqual(validUntil)
      expect(validityInfo.expectedUpdate).toBeUndefined()
    })

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device')).toEqual(new Map([['test', 1234]]))
    })

    it('should generate the signature without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceSignature?.payload).toBeNull()
    })

    it('should match session transcript generated by OpenID Conformance Test Suite', async () => {
      const sessionTranscriptBytes = await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VPDCApi({
        context: mdocContext,
        clientId: 'localhost.emobix.co.uk',
        origin: 'https://localhost.emobix.co.uk:8443',
        verifierGeneratedNonce: '8sigA7tG9GnYfWeRfrAG5PMpHOif-._~',
      })

      const sessionTranscript = (cborDecode(sessionTranscriptBytes) as DataItem).data

      // This is only cbor encoded, not with DataItem (so it's NOT Session transcript bytes)
      expect(Buffer.from(cborEncode(sessionTranscript)).toString('base64')).toEqual(
        'g/b2gnZPcGVuSUQ0VlBEQ0FQSUhhbmRvdmVyWCBd0cMpz6ie3V5hrfH0TMRNv/K/U1jcr0o2rN+i0gMNWA=='
      )
    })

    it('should match session transcript generated by BDR', async () => {
      const sessionTranscriptBytes = await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VPDCApi({
        context: mdocContext,
        clientId: 'web-origin:https://digital-credentials.dev',
        origin: 'https://digital-credentials.dev',
        verifierGeneratedNonce: '8tHrpFyi2QQUcISKvC5rq53y-G80Yx0qU6Z5kB_eNkI',
      })

      expect(Buffer.from(sessionTranscriptBytes).toString('base64url')).toEqual(
        '2BhYPYP29oJ2T3BlbklENFZQRENBUElIYW5kb3ZlclggVfi7Xfza4-PMoSE83fTiP5uSH_VKop2TJb0nUE4yBrI'
      )
    })
  })

  describe('using WebAPI handover', () => {
    // The actual value for the engagements & the key do not matter,
    // as long as the device and the reader agree on what value to use.
    const eReaderKeyBytes: Buffer = randomFillSync(Buffer.alloc(32))
    const readerEngagementBytes = randomFillSync(Buffer.alloc(32))
    const deviceEngagementBytes = randomFillSync(Buffer.alloc(32))

    beforeAll(async () => {
      // Nothing more to do on the verifier side.

      // This is the Device side
      {
        const devicePrivateKey = DEVICE_JWK
        const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
          .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
          .usingSessionTranscriptForWebAPI({
            deviceEngagementBytes,
            readerEngagementBytes,
            eReaderKeyBytes,
          })
          .authenticateWithSignature(devicePrivateKey, 'ES256')
          .addDeviceNameSpace('com.foobar-device', { test: 1234 })
          .sign(mdocContext)
        encodedDeviceResponse = deviceResponseMDoc.encode()
      }

      const parsedMDOC = parseDeviceResponse(encodedDeviceResponse)
      ;[parsedDocument] = parsedMDOC.documents as [DeviceSignedDocument, ...DeviceSignedDocument[]]
    })

    it('should be verifiable', async () => {
      const verifier = new Verifier()
      await verifier.verifyDeviceResponse(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          encodedDeviceResponse,
          encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({
            context: mdocContext,
            readerEngagementBytes,
            deviceEngagementBytes,
            eReaderKeyBytes,
          }),
        },
        mdocContext
      )
    })

    describe('should not be verifiable', () => {
      const wrong = randomFillSync(Buffer.alloc(32))
      const testCases = ['eReaderKeyBytes', 'deviceEngagementBytes', 'readerEngagementBytes']

      testCases.forEach((name) => {
        const values = {
          eReaderKeyBytes,
          deviceEngagementBytes,
          readerEngagementBytes,
          [name]: wrong,
        }
        it(`with a different ${name}`, async () => {
          const verifier = new Verifier()
          try {
            await verifier.verifyDeviceResponse(
              {
                trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
                encodedDeviceResponse,
                encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({
                  context: mdocContext,
                  readerEngagementBytes: values.readerEngagementBytes,
                  deviceEngagementBytes: values.deviceEngagementBytes,
                  eReaderKeyBytes: values.eReaderKeyBytes,
                }),
              },
              mdocContext
            )
            throw new Error('should not validate with different transcripts')
          } catch (error) {
            expect((error as Error).message).toMatch(
              'Unable to verify deviceAuth signature (ECDSA/EdDSA): Device signature must be valid'
            )
          }
        })
      })
    })

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.mobileSecurityObject
      expect(validityInfo).toBeDefined()
      expect(validityInfo.signed).toEqual(signed)
      expect(validityInfo.validFrom).toEqual(signed)
      expect(validityInfo.validUntil).toEqual(validUntil)
      expect(validityInfo.expectedUpdate).toBeUndefined()
    })

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device')).toEqual(new Map([['test', 1234]]))
    })

    it('should generate the signature without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceSignature?.payload).toBeNull()
    })
  })

  describe('using Device Request instead of presentation definition', () => {
    // The actual value for the engagements & the key do not matter,
    // as long as the device and the reader agree on what value to use.
    const eReaderKeyBytes: Buffer = randomFillSync(Buffer.alloc(32))
    const readerEngagementBytes = randomFillSync(Buffer.alloc(32))
    const deviceEngagementBytes = randomFillSync(Buffer.alloc(32))
    let encodedDeviceResponse: Uint8Array

    const getSessionTranscriptBytes = (rdrEngtBytes: Buffer, devEngtBytes: Buffer, eRdrKeyBytes: Buffer) =>
      cborEncode(
        DataItem.fromData([
          new DataItem({ buffer: devEngtBytes }),
          new DataItem({ buffer: eRdrKeyBytes }),
          rdrEngtBytes,
        ])
      )

    beforeAll(async () => {
      // Nothing more to do on the verifier side.

      // This is the Device side
      {
        const devicePrivateKey = DEVICE_JWK
        const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
          .usingDeviceRequest(deviceRequest)
          .usingSessionTranscriptForWebAPI({
            deviceEngagementBytes,
            readerEngagementBytes,
            eReaderKeyBytes,
          })
          .authenticateWithSignature(devicePrivateKey, 'ES256')
          .addDeviceNameSpace('com.foobar-device', { test: 1234 })
          .sign(mdocContext)
        encodedDeviceResponse = deviceResponseMDoc.encode()
      }

      const parsedMDOC = parseDeviceResponse(encodedDeviceResponse)
      ;[parsedDocument] = parsedMDOC.documents as [DeviceSignedDocument, ...DeviceSignedDocument[]]
    })

    it('should be verifiable', async () => {
      const verifier = new Verifier()
      await verifier.verifyDeviceResponse(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          encodedDeviceResponse,
          encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({
            context: mdocContext,
            readerEngagementBytes,
            deviceEngagementBytes,
            eReaderKeyBytes,
          }),
        },
        mdocContext
      )
    })

    describe('should not be verifiable', () => {
      const wrong = randomFillSync(Buffer.alloc(32))
      const testCases = ['readerEngagementBytes', 'deviceEngagementBytes', 'eReaderKeyBytes']

      testCases.forEach((name) => {
        const values = {
          eReaderKeyBytes,
          deviceEngagementBytes,
          readerEngagementBytes,
          [name]: wrong,
        }
        it(`with a different ${name}`, async () => {
          const verifier = new Verifier()
          try {
            await verifier.verifyDeviceResponse(
              {
                trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
                encodedDeviceResponse,
                encodedSessionTranscript: getSessionTranscriptBytes(
                  values.readerEngagementBytes,
                  values.deviceEngagementBytes,
                  values.eReaderKeyBytes
                ),
              },
              mdocContext
            )
            throw new Error('should not validate with different transcripts')
          } catch (error) {
            expect((error as Error).message).toMatch(
              'Unable to verify deviceAuth signature (ECDSA/EdDSA): Device signature must be valid'
            )
          }
        })
      })
    })

    it('should contain the validity info', () => {
      const { validityInfo } = parsedDocument.issuerSigned.issuerAuth.mobileSecurityObject
      expect(validityInfo).toBeDefined()
      expect(validityInfo.signed).toEqual(signed)
      expect(validityInfo.validFrom).toEqual(signed)
      expect(validityInfo.validUntil).toEqual(validUntil)
      expect(validityInfo.expectedUpdate).toBeUndefined()
    })

    it('should contain all requested claims', () => {
      const namespaces = parsedDocument.allIssuerSignedNamespaces
      expect(namespaces).toStrictEqual(
        new Map([
          [
            'org.iso.18013.5.1',
            new Map(
              Object.entries({
                family_name: 'Jones',
                birth_date: '2007-03-25',
                document_number: '01-856-5050',
                given_name: 'Ava',
                driving_privileges: [expect.any(Map)],
                expiry_date: '2028-09-30',
                issue_date: '2023-09-01',
                issuing_authority: 'NY DMV',
                issuing_country: 'US',
                issuing_jurisdiction: 'New York',
                portrait: 'bstr',
                un_distinguishing_sign: 'tbd-us.ny.dmv',
              })
            ),
          ],
        ])
      )
    })

    it('should contain the device namespaces', () => {
      expect(parsedDocument.getDeviceNameSpace('com.foobar-device')).toEqual(new Map([['test', 1234]]))
    })

    it('should generate the signature without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceSignature?.payload).toBeNull()
    })
  })
})
