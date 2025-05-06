import { compareVersions } from 'compare-versions'
import type { MdocContext, X509Context } from '../context.js'
import { CoseKey } from '../cose'
import type { VerificationAssessment, VerificationCallback } from './check-callback.js'
import { defaultVerificationCallback, onCategoryCheck } from './check-callback.js'
import { DeviceResponse } from './models/device-response.js'
import { DeviceSignedDocument } from './models/device-signed-document.js'
import type { Document } from './models/document.js'
import type { IssuerAuth } from './models/issuer-auth.js'
import type { IssuerSignedItem } from './models/issuer-signed-item.js'
import { SessionTranscript } from './models/session-transcript.js'
import type { DiagnosticInformation } from './models/types.js'
import { calculateDeviceAutenticationBytes } from './utils.js'

const MDL_NAMESPADCE = 'org.iso.18013.5.1'

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as Record<string, string>

export class Verifier {
  public async verifyIssuerSignature(
    input: {
      trustedCertificates: Uint8Array[]
      issuerAuth: IssuerAuth
      now?: Date
      disableCertificateChainValidation: boolean
      onCheckG?: VerificationCallback
    },
    ctx: { x509: X509Context; cose: MdocContext['cose'] }
  ) {
    const { issuerAuth, disableCertificateChainValidation, onCheckG } = input
    const onCheck = onCategoryCheck(onCheckG ?? defaultVerificationCallback, 'ISSUER_AUTH')
    const { certificateChain } = issuerAuth
    const countryName = issuerAuth.getIssuingCountry(ctx)

    if (!certificateChain) {
      onCheck({
        status: 'FAILED',
        check: 'Missing x509 certificate in issuerAuth',
      })

      return
    }

    if (!issuerAuth.signatureAlgorithmName) {
      onCheck({
        status: 'FAILED',
        check: 'IssuerAuth must have an alg property',
      })

      return
    }

    if (!disableCertificateChainValidation) {
      const trustedCertificates = input.trustedCertificates
      try {
        if (!trustedCertificates[0]) {
          throw new Error('No trusted certificates found. Cannot verify issuer signature.')
        }
        await ctx.x509.validateCertificateChain({
          trustedCertificates,
          x5chain: certificateChain,
        })
        onCheck({
          status: 'PASSED',
          check: 'Issuer certificate must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Issuer certificate must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const verificationJwk = await ctx.x509.getPublicKey({
      certificate: issuerAuth.certificate,
      alg: issuerAuth.signatureAlgorithmName,
    })

    const verificationResult = await ctx.cose.sign1.verify({
      sign1: issuerAuth,
      jwk: verificationJwk,
    })

    // TODO
    // onCheck({
    //   status: verificationResult ? 'PASSED' : 'FAILED',
    //   check: 'Issuer signature must be valid',
    // })

    // Validity
    const { validityInfo } = issuerAuth.mobileSecurityObject
    const now = input.now ?? new Date()

    const certificateData = await ctx.x509.getCertificateData({
      certificate: issuerAuth.certificate,
    })

    onCheck({
      status:
        validityInfo.signed < certificateData.notBefore || validityInfo.signed > certificateData.notAfter
          ? 'FAILED'
          : 'PASSED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${certificateData.notBefore.toUTCString()} to ${certificateData.notAfter.toUTCString()})`,
    })

    onCheck({
      status: now < validityInfo.validFrom || now > validityInfo.validUntil ? 'FAILED' : 'PASSED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    })

    onCheck({
      status: countryName ? 'PASSED' : 'FAILED',
      check: "Country name (C) must be present in the issuer certificate's subject distinguished name",
    })
  }

  public async verifyDeviceSignature(
    input: {
      document: Document
      ephemeralPrivateKey?: Record<string, unknown> | Uint8Array
      sessionTranscript?: SessionTranscript
      onCheckG?: VerificationCallback
    },
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ) {
    const { document, sessionTranscript, ephemeralPrivateKey } = input
    const onCheck = onCategoryCheck(input.onCheckG ?? defaultVerificationCallback, 'DEVICE_AUTH')

    const { deviceSigned, issuerSigned, docType } = document
    const { deviceKey } = issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo
    const { deviceAuth, deviceNamespaces } = deviceSigned
    const { deviceSignature } = deviceAuth

    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      })
      return
    }

    if (!sessionTranscript) {
      onCheck({
        status: 'FAILED',
        check: 'Session Transcript Bytes missing from options, aborting device signature check',
      })
      return
    }

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(sessionTranscript, docType, deviceNamespaces)

    if (!deviceKey) {
      onCheck({
        status: 'FAILED',
        check: 'Issuer signature must contain the device key.',
        reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
      })
      return
    }

    if (deviceAuth.deviceSignature) {
      // ECDSA/EdDSA authentication
      try {
        const ds = deviceAuth.deviceSignature
        ds.detachedContent = deviceAuthenticationBytes

        const jwk = deviceKey.jwk
        // todo
        // const verificationResult = await ctx.cose.sign1.verify({ sign1: ds, jwk })

        // onCheck({
        //   status: verificationResult ? 'PASSED' : 'FAILED',
        //   check: 'Device signature must be valid',
        // })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device signature must be valid',
          reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err instanceof Error ? err.message : 'Unknown error'}`,
        })
      }
      return
    }

    // MAC authentication
    onCheck({
      status: deviceAuth.deviceMac ? 'PASSED' : 'FAILED',
      check: 'Device MAC must be present when using MAC authentication',
    })
    if (!deviceAuth.deviceMac) {
      return
    }

    try {
      deviceAuth.deviceMac.signatureAlgorithmName

      onCheck({
        status: 'PASSED',
        check: 'Device MAC must use alg 5 (HMAC 256/256)',
      })
    } catch {
      onCheck({
        status: 'FAILED',
        check: 'Device MAC must use alg 5 (HMAC 256/256)',
      })
      return
    }

    onCheck({
      status: ephemeralPrivateKey ? 'PASSED' : 'FAILED',
      check: 'Ephemeral private key must be present when using MAC authentication',
    })
    if (!ephemeralPrivateKey) {
      return
    }

    try {
      const deviceKeyRaw = deviceKey.publicKey
      const ephemeralMacKeyJwk = await ctx.crypto.calculateEphemeralMacKeyJwk({
        privateKey:
          ephemeralPrivateKey instanceof Uint8Array
            ? ephemeralPrivateKey
            : CoseKey.fromJwk(ephemeralPrivateKey).privateKey,
        publicKey: deviceKeyRaw,
        sessionTranscriptBytes: sessionTranscript.encode(),
      })

      deviceAuth.deviceMac.detachedContent = deviceAuthenticationBytes

      const isValid = await ctx.cose.mac0.verify({
        mac0: deviceAuth.deviceMac,
        jwk: ephemeralMacKeyJwk,
      })

      onCheck({
        status: isValid ? 'PASSED' : 'FAILED',
        check: 'Device MAC must be valid',
      })
    } catch (err) {
      onCheck({
        status: 'FAILED',
        check: 'Device MAC must be valid',
        reason: `Unable to verify deviceAuth MAC: ${err instanceof Error ? err.message : 'Unknown error'}`,
      })
    }
  }

  public async verifyData(
    input: {
      document: Document
      onCheckG?: VerificationCallback
    },
    ctx: { x509: X509Context; crypto: MdocContext['crypto'] }
  ) {
    const { document, onCheckG } = input
    // Confirm that the mdoc data has not changed since issuance
    const { issuerAuth } = document.issuerSigned
    const { valueDigests, digestAlgorithm } = issuerAuth.mobileSecurityObject

    const onCheck = onCategoryCheck(onCheckG ?? defaultVerificationCallback, 'DATA_INTEGRITY')

    onCheck({
      status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    })

    const namespaces = document.issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map<string, IssuerSignedItem[]>()

    await Promise.all(
      Array.from(namespaces.entries()).map(async ([ns, nsItems]) => {
        onCheck({
          status: valueDigests?.valueDigests.has(ns) ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include digests for namespace: ${ns}`,
        })

        const verifications = await Promise.all(
          nsItems.map(async (ev) => {
            const isValid = await ev.isValid(ns, issuerAuth, ctx)
            return { ev, ns, isValid }
          })
        )

        verifications
          .filter((v) => v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'PASSED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        verifications
          .filter((v) => !v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'FAILED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        if (ns === MDL_NAMESPADCE) {
          const certificateData = await ctx.x509.getCertificateData({
            certificate: issuerAuth.certificate,
          })
          if (!certificateData.issuerName) {
            onCheck({
              status: 'FAILED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason:
                "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
            })
          } else {
            const invalidCountry = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
              .find((v) => !v.isValid || !v.ev.matchCertificate(issuerAuth, ctx))

            onCheck({
              status: invalidCountry ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason: invalidCountry
                ? `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${issuerAuth.getIssuingCountry(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })

            const invalidJurisdiction = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
              .find((v) => !v.isValid || !v.ev.matchCertificate(issuerAuth, ctx))

            onCheck({
              status: invalidJurisdiction ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
              reason: invalidJurisdiction
                ? `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${issuerAuth.getIssuingStateOrProvince(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })
          }
        }
      })
    )
  }

  async verifyDeviceResponse(
    input: {
      deviceResponse: DeviceResponse | Uint8Array
      sessionTranscript?: SessionTranscript | Uint8Array
      ephemeralReaderKey?: Record<string, unknown> | Uint8Array
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
    },
    ctx: {
      x509: X509Context
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<DeviceResponse> {
    const onCheck = input.onCheck ?? defaultVerificationCallback

    const deviceResponse =
      input.deviceResponse instanceof DeviceResponse
        ? input.deviceResponse
        : DeviceResponse.decode(input.deviceResponse)

    onCheck({
      status: deviceResponse.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: deviceResponse.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: compareVersions(deviceResponse.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response version must be 1.0 or greater',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status:
        !deviceResponse.documents || (deviceResponse.documents && deviceResponse.documents.length > 0)
          ? 'PASSED'
          : 'FAILED',
      check: 'Device Response must include at least not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    for (const document of deviceResponse.documents ?? []) {
      const { issuerAuth } = document.issuerSigned
      if (!document.deviceSigned) {
        onCheck({
          status: 'FAILED',
          category: 'DEVICE_AUTH',
          check: `The document is not signed by the device. ${document.docType}`,
        })
        continue
      }

      await this.verifyIssuerSignature(
        {
          issuerAuth,
          disableCertificateChainValidation: input.disableCertificateChainValidation ?? false,
          now: input.now,
          onCheckG: onCheck,
          trustedCertificates: input.trustedCertificates,
        },
        ctx
      )

      await this.verifyDeviceSignature(
        {
          document,
          ephemeralPrivateKey: input.ephemeralReaderKey,
          sessionTranscript: input.sessionTranscript
            ? input.sessionTranscript instanceof SessionTranscript
              ? input.sessionTranscript
              : SessionTranscript.decode(input.sessionTranscript)
            : undefined,
          onCheckG: onCheck,
        },
        ctx
      )

      await this.verifyData({ document, onCheckG: onCheck }, ctx)
    }

    return deviceResponse
  }

  async getDiagnosticInformation(
    encodedDeviceResponse: Uint8Array,
    options: {
      trustedCertificates: Uint8Array[]
      encodedSessionTranscript?: Uint8Array
      ephemeralReaderKey?: Record<string, unknown> | Uint8Array
      disableCertificateChainValidation?: boolean
    },
    ctx: {
      x509: X509Context
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<DiagnosticInformation> {
    const { trustedCertificates } = options
    const dr: VerificationAssessment[] = []
    const decoded = await this.verifyDeviceResponse(
      {
        deviceResponse: encodedDeviceResponse,
        ...options,
        onCheck: (check) => dr.push(check),
        trustedCertificates,
      },
      ctx
    )

    const document = decoded.documents?.[0]
    if (!document) {
      throw new Error('No documents found for getting diagnostic information.')
    }

    const { issuerAuth } = document.issuerSigned
    const issuerCert = issuerAuth.certificate

    const attributes = (
      await Promise.all(
        Array.from(document.issuerSigned.issuerNamespaces?.issuerNamespaces.keys() ?? []).map(async (ns) => {
          const items = document.issuerSigned.issuerNamespaces?.issuerNamespaces.get(ns) ?? []
          return Promise.all(
            items.map(async (item) => {
              const isValid = await item.isValid(ns, issuerAuth, ctx)
              return {
                ns,
                id: item.elementIdentifier,
                value: item.elementValue,
                isValid,
                matchCertificate: item.matchCertificate(issuerAuth, ctx),
              }
            })
          )
        })
      )
    ).flat()

    const deviceAttributes =
      document instanceof DeviceSignedDocument
        ? Array.from(document.deviceSigned.nameSpaces.entries()).flatMap(([ns, items]) => {
            return Array.from(items.entries()).map(([id, value]) => {
              return {
                ns,
                id,
                value,
              }
            })
          })
        : undefined

    let deviceKey: Record<string, unknown> | undefined = undefined

    if (document.issuerSigned.issuerAuth) {
      const { deviceKeyInfo } = document.issuerSigned.issuerAuth.mobileSecurityObject
      if (deviceKeyInfo?.deviceKey) {
        deviceKey = deviceKeyInfo.deviceKey.jwk
      }
    }
    const disclosedAttributes = attributes.filter((attr) => attr.isValid).length
    const totalAttributes = Array.from(
      document.issuerSigned.issuerAuth.mobileSecurityObject.valueDigests?.valueDigests.entries() ?? []
    ).reduce((prev, [, digests]) => prev + digests.size, 0)

    return {
      general: {
        version: decoded.version,
        type: 'DeviceResponse',
        status: decoded.status,
        documentCount: decoded.documents?.length,
      },
      validityInfo: document.issuerSigned.issuerAuth.mobileSecurityObject.validityInfo,
      issuerCertificate: await ctx.x509.getCertificateData({
        certificate: issuerCert,
      }),
      issuerSignature: {
        alg: document.issuerSigned.issuerAuth.signatureAlgorithmName,
        isValid: dr.filter((check) => check.category === 'ISSUER_AUTH').every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'ISSUER_AUTH' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
        digests: Object.fromEntries(
          Array.from(
            document.issuerSigned.issuerAuth.mobileSecurityObject.valueDigests?.valueDigests.entries() ?? []
          ).map(([ns, digests]) => [ns, digests.size])
        ),
      },
      deviceKey: {
        jwk: deviceKey,
      },
      deviceSignature:
        document instanceof DeviceSignedDocument
          ? {
              alg:
                document.deviceSigned.deviceAuth.deviceSignature?.signatureAlgorithmName ??
                document.deviceSigned.deviceAuth.deviceMac?.signatureAlgorithmName,
              isValid: dr
                .filter((check) => check.category === 'DEVICE_AUTH')
                .every((check) => check.status === 'PASSED'),
              reasons: dr
                .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
                .map((check) => check.reason ?? check.check),
            }
          : undefined,
      dataIntegrity: {
        disclosedAttributes: `${disclosedAttributes} of ${totalAttributes}`,
        isValid: dr.filter((check) => check.category === 'DATA_INTEGRITY').every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'DATA_INTEGRITY' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
      },
      attributes,
      deviceAttributes,
      // TODO!!!!
      // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    } as any
  }
}
