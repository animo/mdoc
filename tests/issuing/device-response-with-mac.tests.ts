import { randomFillSync } from 'node:crypto'
import { X509Certificate } from '@peculiar/x509'
import type { JWK } from 'jose'
import * as jose from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import type { DeviceSignedDocument } from '../../src'
import { DeviceResponseOld, Document, MDoc, Verifier, parseDeviceResponse } from '../../src'
import { mdocContext } from '../context'
import { DEVICE_JWK, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK, PRESENTATION_DEFINITION_1 } from './config.js'
const { d, ...publicKeyJWK } = DEVICE_JWK

describe.skip('issuing a device response with MAC authentication', () => {
  let encodedDeviceResponse: Uint8Array
  let parsedDocument: DeviceSignedDocument
  let mdoc: MDoc
  let ephemeralPrivateKey: JWK
  let ephemeralPublicKey: JWK

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
              issue_date: '2022-09-01',
              expiry_date: '2027-09-30',
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

      // This is the verifier side before requesting the Device Response
      {
        const ephemeralKey = await jose.exportJWK((await jose.generateKeyPair('ES256')).privateKey)
        const { d: _1, ...ephemeralKeyPublic } = ephemeralKey
        ephemeralPrivateKey = ephemeralKey
        ephemeralPublicKey = ephemeralKeyPublic
      }
    }
  })

  describe('using OID4VP handover', () => {
    const verifierGeneratedNonce = 'abcdefg'
    const mdocGeneratedNonce = '123456'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback'

    beforeAll(async () => {
      //  This is the Device side
      const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
        .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
        .usingSessionTranscriptForOID4VP({
          mdocGeneratedNonce,
          clientId,
          responseUri,
          verifierGeneratedNonce,
        })
        .authenticateWithMAC(DEVICE_JWK, ephemeralPublicKey, 'HS256')
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
          deviceResponse: encodedDeviceResponse,
          ephemeralReaderKey: ephemeralPrivateKey,
          sessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({
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
                deviceResponse: encodedDeviceResponse,
                trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
                ephemeralReaderKey: ephemeralPrivateKey,
                sessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({
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
            expect((error as Error).message).toMatch('Unable to verify deviceAuth MAC: Device MAC must be valid')
          }
        })
      })
    })

    it('should generate a device mac without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceMac?.payload).toBeNull()
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
  })

  describe('using WebAPI handover', () => {
    // The actual value for the engagements & the key do not matter,
    // as long as the device and the reader agree on what value to use.
    const eReaderKeyBytes: Buffer = randomFillSync(Buffer.alloc(32))
    const readerEngagementBytes = randomFillSync(Buffer.alloc(32))
    const deviceEngagementBytes = randomFillSync(Buffer.alloc(32))

    beforeAll(async () => {
      // This is the verifier side before requesting the Device Response
      {
        const ephemeralKey = await jose.exportJWK((await jose.generateKeyPair('ES256')).privateKey)
        ephemeralPrivateKey = ephemeralKey
        const { d: _1, ...ephemeralKeyPublic } = ephemeralKey
        ephemeralPublicKey = ephemeralKeyPublic
      }

      //  This is the Device side
      {
        const deviceResponseMDoc = await DeviceResponseOld.from(mdoc)
          .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
          .usingSessionTranscriptForWebAPI({
            deviceEngagementBytes,
            readerEngagementBytes,
            eReaderKeyBytes,
          })
          .authenticateWithMAC(DEVICE_JWK, ephemeralPublicKey, 'HS256')
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
          deviceResponse: encodedDeviceResponse,
          ephemeralReaderKey: ephemeralPrivateKey,
          sessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({
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
                deviceResponse: encodedDeviceResponse,
                ephemeralReaderKey: ephemeralPrivateKey,
                sessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({
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
            expect((error as Error).message).toMatch('Unable to verify deviceAuth MAC: Device MAC must be valid')
          }
        })
      })
    })

    it('should generate a device mac without payload', () => {
      expect(parsedDocument.deviceSigned.deviceAuth.deviceMac?.payload).toBeNull()
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
  })
})
