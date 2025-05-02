import { describe, test } from 'vitest'
import { SessionTranscript, Verifier } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate } from './issuerCertificate'

describe('Ubique mdoc implementation', () => {
  test('verify DeviceResponse from Ubique', async () => {
    const verifierGeneratedNonce = 'abcdefg'
    const mdocGeneratedNonce = '123456'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback'

    const verifier = new Verifier()
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
        deviceResponse: deviceResponse,
        sessionTranscript: await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
          {
            clientId,
            responseUri,
            verifierGeneratedNonce,
            mdocGeneratedNonce,
          },
          mdocContext
        ),
        now: new Date('2025-02-01'),
      },
      mdocContext
    )
  })
})
