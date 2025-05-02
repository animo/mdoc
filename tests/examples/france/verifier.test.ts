import { describe, it } from 'vitest'
import { DeviceResponseOld, Verifier } from '../../../src/'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate } from './issuerCertificate'

describe('French playground mdoc implementation', () => {
  it('should verify DeviceResponse from French playground', async () => {
    const verifierGeneratedNonce = 'abcdefgh1234567890'
    const mdocGeneratedNonce = ''
    const clientId = 'example.com'
    const responseUri = 'https://example.com/12345/response'

    const verifier = new Verifier()
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
        encodedDeviceResponse: deviceResponse,
        encodedSessionTranscript: await DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({
          context: mdocContext,
          clientId,
          responseUri,
          verifierGeneratedNonce,
          mdocGeneratedNonce,
        }),
        now: new Date('2021-09-25'),
      },
      mdocContext
    )
  })
})
