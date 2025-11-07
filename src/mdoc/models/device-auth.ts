import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { type CoseKey, MacAlgorithm } from '../../cose'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { MdlError } from '../errors'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac, type DeviceMacStructure } from './device-mac'
import { DeviceSignature, type DeviceSignatureStructure } from './device-signature'
import type { Document } from './document'
import type { SessionTranscript } from './session-transcript'

export type DeviceAuthStructure = {
  deviceSignature?: DeviceSignatureStructure
  deviceMac?: DeviceMacStructure
}

export type DeviceAuthOptions = {
  deviceSignature?: DeviceSignature
  deviceMac?: DeviceMac
}

export class DeviceAuth extends CborStructure {
  public deviceSignature?: DeviceSignature
  public deviceMac?: DeviceMac

  public constructor(options: DeviceAuthOptions) {
    super()

    this.deviceSignature = options.deviceSignature
    this.deviceMac = options.deviceMac

    this.assertEitherMacOrSignature()
  }

  private assertEitherMacOrSignature() {
    if (this.deviceMac && this.deviceSignature) {
      throw new MdlError('deviceAuth can only contain either a deviceMac or deviceSignature')
    }

    if (!this.deviceMac && !this.deviceSignature) {
      throw new MdlError('deviceAuth must contain either a deviceMac or deviceSignature')
    }
  }

  public encodedStructure(): DeviceAuthStructure {
    this.assertEitherMacOrSignature()

    if (this.deviceSignature) {
      return {
        deviceSignature: this.deviceSignature.encodedStructure(),
      }
    }

    if (this.deviceMac) {
      return {
        deviceMac: this.deviceMac.encodedStructure(),
      }
    }

    throw new MdlError('unreachable')
  }

  public async validate(
    options: {
      document: Document
      verificationCallback?: VerificationCallback
      ephemeralMacPrivateKey?: CoseKey
      sessionTranscript: SessionTranscript
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'DEVICE_AUTH')

    const { deviceKey } = options.document.issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo

    if (!this.deviceMac && !this.deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      })
      return
    }

    const deviceAuthenticationBytes = new DeviceAuthentication({
      sessionTranscript: options.sessionTranscript,
      docType: options.document.docType,
      deviceNamespaces: options.document.deviceSigned.deviceNamespaces,
    }).encode({ asDataItem: true })

    if (this.deviceSignature) {
      try {
        const ds = this.deviceSignature
        ds.detachedContent = deviceAuthenticationBytes

        const verificationResult = await ctx.cose.sign1.verify({ sign1: ds, key: deviceKey })

        onCheck({
          status: verificationResult ? 'PASSED' : 'FAILED',
          check: 'Device signature must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device signature must be valid',
          reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err instanceof Error ? err.message : 'Unknown error'}`,
        })
      }
      return
    }

    if (this.deviceMac) {
      try {
        this.deviceMac.signatureAlgorithmName === MacAlgorithm.HS256
      } catch {
        onCheck({
          status: 'FAILED',
          check: 'Device MAC must use alg 5 (HMAC 256/256)',
        })
        return
      }

      onCheck({
        status: options.ephemeralMacPrivateKey ? 'PASSED' : 'FAILED',
        check: 'Ephemeral private key must be present when using MAC authentication',
      })

      if (!options.ephemeralMacPrivateKey) {
        return
      }

      try {
        this.deviceMac.detachedContent = deviceAuthenticationBytes

        const isValid = await this.deviceMac.verify(
          {
            publicKey: deviceKey,
            privateKey: options.ephemeralMacPrivateKey,
            sessionTranscript: options.sessionTranscript,
            info: 'EMacKey',
          },
          ctx
        )

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

    onCheck({
      status: 'FAILED',
      check: 'No Device Signature or Device Mac found on Device Auth',
      reason: 'No Device Signature or Device Mac found on Device Auth',
    })
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceAuthStructure | Map<string, unknown>
  ): DeviceAuth {
    let structure = encodedStructure as DeviceAuthStructure

    if (encodedStructure instanceof Map) {
      structure = {
        deviceMac: encodedStructure.get('deviceMac') as DeviceAuthStructure['deviceMac'],
        deviceSignature: encodedStructure.get('deviceSignature') as DeviceAuthStructure['deviceSignature'],
      }
    }

    return new DeviceAuth({
      deviceSignature: structure.deviceSignature
        ? DeviceSignature.fromEncodedStructure(structure.deviceSignature)
        : undefined,
      deviceMac: structure.deviceMac ? DeviceMac.fromEncodedStructure(structure.deviceMac) : undefined,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceAuth {
    const structure = cborDecode<DeviceAuthStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    return DeviceAuth.fromEncodedStructure(structure)
  }
}
