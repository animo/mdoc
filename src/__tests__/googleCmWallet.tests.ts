import { X509Certificate } from '@peculiar/x509'
import { describe, it } from 'vitest'
import { mdocContext } from '.'
import { DeviceResponse } from '../mdoc/model/device-response'
import { Verifier } from '../mdoc/verifier'

const ROOT_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIB7zCCAZWgAwIBAgIUPEQW7teE87QT5I9W8HWr+m2H64QwCgYIKoZIzj0EAwIw
IzEUMBIGA1UEAwwLdXRvcGlhIGlhY2ExCzAJBgNVBAYTAlVTMB4XDTIwMTAwMTAw
MDAwMFoXDTIxMTAwMTAwMDAwMFowITESMBAGA1UEAwwJdXRvcGlhIGRzMQswCQYD
VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKznq3NA5dlkjFpyqab1
Z0XHqtQ2oDpD7+p3tfp7iPAZfVfYmD4bN9OlOfTViDZeOMu/W5TWjFR7W8hzHc0v
FGujgagwgaUwHgYDVR0SBBcwFYETZXhhbXBsZUBleGFtcGxlLmNvbTAcBgNVHR8E
FTATMBGgD6ANggtleGFtcGxlLmNvbTAdBgNVHQ4EFgQUFOKQF6bDViH/x6aGt7ct
sGzRI1EwHwYDVR0jBBgwFoAUVPojg6BMKODZMHkiYcgMSIHSwAswDgYDVR0PAQH/
BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwCgYIKoZIzj0EAwIDSAAwRQIh
AJdxerkBZ0DI17zapJSmLAU7vezOE4PBrKcq0I28BMuyAiA7rYWcE6Y8bRrWfYFN
Q+JCXK+Q1CJCLASo7gMEwNOmjQ==
-----END CERTIFICATE-----`
const SIGNING_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIICwDCCAmegAwIBAgIUHn8bMq1PNO/ksMwHt7DjM6cLGE0wCgYIKoZIzj0EAwIw
eTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1v
dW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNV
BAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwHhcNMjUwMjE5MjMzMDE4WhcNMjYw
MjE5MjMzMDE4WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW
MBQGA1UEBwwNTW91bnRhaW4gVmlldzEcMBoGA1UECgwTRGlnaXRhbCBDcmVkZW50
aWFsczEfMB0GA1UEAwwWZGlnaXRhbGNyZWRlbnRpYWxzLmRldjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABOt5Nivi1/OXw1AEfYPh42Is41VrNg9qaMdYuw3cavhs
Ca+aXV0NmTl2EsNaJ5GWmMoAD8ikwAFszYhIeNgF42mjgcwwgckwHwYDVR0jBBgw
FoAUok/0idl8Ruhuo4bZR0jOzL7cz/UwHQYDVR0OBBYEFN/+aloS6cBixLyYpyXS
2XD3emAoMDQGA1UdHwQtMCswKaAnoCWGI2h0dHBzOi8vZGlnaXRhbC1jcmVkZW50
aWFscy5kZXYvY3JsMCoGA1UdEgQjMCGGH2h0dHBzOi8vZGlnaXRhbC1jcmVkZW50
aWFscy5kZXYwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIw
CgYIKoZIzj0EAwIDRwAwRAIgYcXL9XzB43vy4LEz2h8gMQRdcJtaIRQOemgwm8sH
QucCIHCvouHEm/unjBXMCeUZ7QR/ympjGyHITw25/B9H9QsC
-----END CERTIFICATE-----`
const DEVICE_RESPONSE =
  'o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFSkaGRpZ2VzdElEAGZyYW5kb21Qh2ub69pgXPJIlpOYhAJYX3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGjYGFhRpGhkaWdlc3RJRAFmcmFuZG9tUJyft6VAh5wxzh_YqEvXtPBxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVjSm9uamlzc3VlckF1dGiEQ6EBJqEYIVkCxDCCAsAwggJnoAMCAQICFB5_GzKtTzTv5LDMB7ew4zOnCxhNMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKDBNEaWdpdGFsIENyZWRlbnRpYWxzMR8wHQYDVQQDDBZkaWdpdGFsY3JlZGVudGlhbHMuZGV2MB4XDTI1MDIxOTIzMzAxOFoXDTI2MDIxOTIzMzAxOFoweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNVBAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATreTYr4tfzl8NQBH2D4eNiLONVazYPamjHWLsN3Gr4bAmvml1dDZk5dhLDWieRlpjKAA_IpMABbM2ISHjYBeNpo4HMMIHJMB8GA1UdIwQYMBaAFKJP9InZfEbobqOG2UdIzsy-3M_1MB0GA1UdDgQWBBTf_mpaEunAYsS8mKcl0tlw93pgKDA0BgNVHR8ELTArMCmgJ6AlhiNodHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2L2NybDAqBgNVHRIEIzAhhh9odHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2MA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoGCCqGSM49BAMCA0cAMEQCIGHFy_V8weN78uCxM9ofIDEEXXCbWiEUDnpoMJvLB0LnAiBwr6LhxJv7p4wVzAnlGe0Ef8pqYxshyE8NufwfR_ULAlkButgYWQG1pmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xowBYIF4np1s8h5zq4R447fmweHJCW6Nd0X9qIlFVmdBckcxQAVgg5epO0W1CanUYkN3my72qMFM_NnUTmlUcXuYpkzhCK8ICWCAA5AsOZa7MqBIVYBoG7kGirGgnXgj2gW5ZN1MtEKKJvm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIITrf6TK84s7dF1jir4ZcQ3mnpOnnBLlOgI_rhbTqBfeIlgg4-d5b1QVCsUwKg3UoYLAn22ttZofjKqX6ajH0Jq7TeJsdmFsaWRpdHlJbmZvo2ZzaWduZWTAeBsyMDI1LTAyLTE5VDIzOjM2OjU4LjIxMDM5MVppdmFsaWRGcm9twHgbMjAyNS0wMi0xOVQyMzozNjo1OC4yMTAzOTlaanZhbGlkVW50aWzAeBsyMDM1LTAyLTA3VDIzOjM2OjU4LjIxMDM5OVpYQH2YP3brP6bfJDJO_FoaPUWwB5LtpYVYKChulL-3yQesOMekny68Gt-G9J3rEZMw7MUI64Y35nWJMqIF_9xB9zFsZGV2aWNlU2lnbmVkompuYW1lU3BhY2Vz2BhBoGpkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqD2WEDHs4neVqi52ED9ea7fj6Skeu-mtHZRwJwN5jAY7sfT7wL-1iVNIIktp6lC4Z_fRoOukVgQn0t1CKrnyEOFe45yZnN0YXR1cwA'

describe('Google CM Wallet mdoc implementation', () => {
  it('should verify DC API DeviceResponse from Google CM Wallet', async () => {
    const verifierGeneratedNonce = 'UwQek7MemM55VM2Lc7UPPsdsxa-vejebSUo75B_G7vk'
    const origin = 'https://ellis-occurrence-ac-smoking.trycloudflare.com'
    const clientId = `web-origin:${origin}`
    const deviceResponse = Buffer.from(DEVICE_RESPONSE, 'base64url')

    const verifier = new Verifier()
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [
          new Uint8Array(new X509Certificate(ROOT_CERTIFICATE).rawData),
          // FIXME: verification fails when only trusting root certificate. We need
          // to trust the signing certificate for now
          new Uint8Array(new X509Certificate(SIGNING_CERTIFICATE).rawData),
        ],
        encodedDeviceResponse: deviceResponse,
        encodedSessionTranscript: await DeviceResponse.calculateSessionTranscriptForOID4VPDCApi({
          context: mdocContext,
          origin,
          clientId,
          verifierGeneratedNonce,
        }),
        now: new Date('2025-02-20'),
      },
      mdocContext
    )
  })
})
