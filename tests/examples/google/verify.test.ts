import { describe, it } from 'vitest'
import { SessionTranscript, Verifier } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { rootCertificate } from './rootCertificate'
import { signingCertificate } from './signingCertificate'

describe('Google CM Wallet mdoc implementation', () => {
  it('should verify DC API DeviceResponse from Google CM Wallet', async () => {
    const verifierGeneratedNonce = 'UwQek7MemM55VM2Lc7UPPsdsxa-vejebSUo75B_G7vk'
    const origin = 'https://ellis-occurrence-ac-smoking.trycloudflare.com'
    const clientId = `web-origin:${origin}`

    const verifier = new Verifier()
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [
          new Uint8Array(rootCertificate.rawData),
          // FIXME: verification fails when only trusting root certificate. We need
          // to trust the signing certificate for now
          new Uint8Array(signingCertificate.rawData),
        ],
        deviceResponse,
        sessionTranscript: await SessionTranscript.calculateSessionTranscriptBytesForOid4VpDcApi(
          {
            origin,
            clientId,
            verifierGeneratedNonce,
          },
          mdocContext
        ),
        now: new Date('2025-02-20'),
      },
      mdocContext
    )
  })
})
