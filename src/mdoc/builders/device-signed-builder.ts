import type { MdocContext } from '../../context'
import {
  type CoseKey,
  Header,
  type MacAlgorithm,
  ProtectedHeaders,
  type SignatureAlgorithm,
  UnprotectedHeaders,
} from '../../cose'
import { base64 } from '../../utils'
import {
  DeviceAuth,
  DeviceMac,
  DeviceNamespaces,
  DeviceSignature,
  DeviceSigned,
  DeviceSignedItems,
  type DocType,
  type Namespace,
  type SessionTranscript,
} from '../models'
import { DeviceAuthentication } from '../models/device-authentication'

export class DeviceSignedBuilder {
  private docType: DocType
  private namespaces: DeviceNamespaces
  private ctx: { cose: MdocContext['cose']; crypto: MdocContext['crypto'] }

  public constructor(docType: DocType, ctx: { cose: MdocContext['cose']; crypto: MdocContext['crypto'] }) {
    this.docType = docType
    this.namespaces = new DeviceNamespaces({ deviceNamespaces: new Map() })
    this.ctx = ctx
  }

  public addDeviceNamespace(namespace: Namespace, value: Record<string, unknown>) {
    const deviceSignedItems =
      this.namespaces.deviceNamespaces.get(namespace) ?? new DeviceSignedItems({ deviceSignedItems: new Map() })

    for (const [k, v] of Object.entries(value)) {
      deviceSignedItems.deviceSignedItems.set(k, v)
    }

    this.namespaces.deviceNamespaces.set(namespace, deviceSignedItems)

    return this
  }

  public async sign(options: {
    signingKey: CoseKey
    algorithm: SignatureAlgorithm
    sessionTranscript: SessionTranscript
    derCertificate: string
  }): Promise<DeviceSigned> {
    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = new UnprotectedHeaders({
      unprotectedHeaders: new Map([[Header.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.signingKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.signingKey.keyId)
    }

    const deviceAuthentication = new DeviceAuthentication({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceSignature = new DeviceSignature({
      unprotectedHeaders,
      protectedHeaders,
      detachedContent: deviceAuthentication.encode({ asDataItem: true }),
    })

    await deviceSignature.addSignature(
      {
        signingKey: options.signingKey,
      },
      this.ctx
    )

    return new DeviceSigned({
      deviceNamespaces: this.namespaces,
      deviceAuth: new DeviceAuth({
        deviceSignature,
      }),
    })
  }

  public async tag(options: {
    publicKey: CoseKey
    privateKey: CoseKey
    sessionTranscript: SessionTranscript
    algorithm: MacAlgorithm
    derCertificate: string
  }): Promise<DeviceSigned> {
    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = new UnprotectedHeaders({
      unprotectedHeaders: new Map([[Header.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.privateKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.privateKey.keyId)
    }

    const deviceAuthentication = new DeviceAuthentication({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceMac = new DeviceMac({
      unprotectedHeaders,
      protectedHeaders,
      detachedContent: deviceAuthentication.encode({ asDataItem: true }),
    })

    await deviceMac.addTag(
      {
        privateKey: options.privateKey,
        ephemeralKey: options.publicKey,
        sessionTranscript: options.sessionTranscript,
      },
      this.ctx
    )

    return new DeviceSigned({
      deviceNamespaces: this.namespaces,
      deviceAuth: new DeviceAuth({
        deviceMac,
      }),
    })
  }
}
