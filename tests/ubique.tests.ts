import { X509Certificate } from '@peculiar/x509'
import { describe, it } from 'vitest'
import { mdocContext } from '.'
import { DeviceResponse } from '../src/mdoc/model/device-response'
import { Verifier } from '../src/mdoc/verifier'

const ISSUER_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBQTCB76ADAgECAiBtxZMzkeRG1H7HmLdQGvZQTeY3NmAVroE8U1glBaBFQzAK
BggqhkjOPQQDAjAeMQ8wDQYDVQQDDAZJc3N1ZXIxCzAJBgNVBAYTAkNIMB4XDTI1
MDEzMDEwNTYwNFoXDTI2MDEzMDEwNTYwNFowHzELMAkGA1UEBhMCQ0gxEDAOBgNV
BAMMB1N1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ2sWdrE5B3m+Xv
09wUBShYmf4V1Rs44oJlotAN2fZKZ86AmgyRYKc1wDYyCFBSVQIDOTh1cvSC2aKk
tb9aRVFMMAoGCCqGSM49BAMCA0EAcgjH/q6Sl4xjuAK3F+1ZxJjZT5iZzcILfFaj
ndzUGIEt+r+NKUBudbinH5yO3/QhRCCZLuhOoOQPsmilkUjqmg==
-----END CERTIFICATE-----`
const DEVICE_RESPONSE =
  'o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBRTCCAUEwge-gAwIBAgIgbcWTM5HkRtR-x5i3UBr2UE3mNzZgFa6BPFNYJQWgRUMwCgYIKoZIzj0EAwIwHjEPMA0GA1UEAwwGSXNzdWVyMQswCQYDVQQGEwJDSDAeFw0yNTAxMzAxMDU2MDRaFw0yNjAxMzAxMDU2MDRaMB8xCzAJBgNVBAYTAkNIMRAwDgYDVQQDDAdTdWJqZWN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENrFnaxOQd5vl79PcFAUoWJn-FdUbOOKCZaLQDdn2SmfOgJoMkWCnNcA2MghQUlUCAzk4dXL0gtmipLW_WkVRTDAKBggqhkjOPQQDAgNBAHIIx_6ukpeMY7gCtxftWcSY2U-Ymc3CC3xWo53c1BiBLfq_jSlAbnW4px-cjt_0IUQgmS7oTqDkD7JopZFI6ppZAaLYGFkBnaZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaMAWCCoCXVh2f3jegnYqJkR-xxgCG2OERNxyJKlXYzjFaDYKgFYIE2tjrQwlw6cmuRAz-a0mHY_VUhjOHpHZidygQAIDHaFAlggXu4HpxuFI2LusYkE67HaztOsyNlPYiRrLA4U6Egmf1ZtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCDEis7CW2GwJAkzQ_JAmVc3t7ChF8JIxPq5q0KwBQ0tYCJYIEFEpLJvRXCaTSim3oTRG-6S4tmzzdeWdkkNTntFFK_7Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI1LTAxLTMwVDEwOjU2OjExWml2YWxpZEZyb23AdDIwMjUtMDEtMzBUMTA6NTY6MTFaanZhbGlkVW50aWzAdDIwMjUtMDItMTNUMTA6NTY6MTFaWEBV1hbSWcPuSXLUMWzJ8TLd7b29O2AZqCaacWm1f3DqIpjSCCXDKRGH3-msEL6RrPgY-pTjyvTivwGLM5FKJZHyam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgdgYWGWkaGRpZ2VzdElEAGZyYW5kb21YIM2DE-hZD3xZJG73iUVma9_thd-lSPDbuxSVC8Bym53ccWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWVKb25lc2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQEKMuH5fCSUyCfJRcae0UyQMh8s1gWPK4qsABDpDd2KUNobbHcR3AYWB-6V4s40UR5m159hhE12-aKa_GR8BPotmc3RhdHVzAA'

describe.skip('Ubique mdoc implementation', () => {
  it('should verify DeviceResponse from Ubique', async () => {
    const verifierGeneratedNonce = 'abcdefg'
    const mdocGeneratedNonce = '123456'
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback'
    const deviceResponse = Buffer.from(DEVICE_RESPONSE, 'base64url')

    const verifier = new Verifier()
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        encodedDeviceResponse: deviceResponse,
        encodedSessionTranscript: await DeviceResponse.calculateSessionTranscriptBytesForOID4VP({
          context: mdocContext,
          clientId,
          responseUri,
          verifierGeneratedNonce,
          mdocGeneratedNonce,
        }),
        now: new Date('2025-02-01'),
      },
      mdocContext
    )
  })
})
