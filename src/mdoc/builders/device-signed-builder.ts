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
  private ctx: Pick<MdocContext, 'cose' | 'crypto'>

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.docType = docType
    this.namespaces = DeviceNamespaces.create({ deviceNamespaces: new Map() })
    this.ctx = ctx
  }

  public addDeviceNamespace(namespace: Namespace, value: Record<string, unknown>) {
    const deviceSignedItems =
      this.namespaces.deviceNamespaces.get(namespace) ?? DeviceSignedItems.create({ deviceSignedItems: new Map() })

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
    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({
      unprotectedHeaders: new Map([[Header.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.signingKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.signingKey.keyId)
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceSignature = await DeviceSignature.create(
      {
        unprotectedHeaders,
        protectedHeaders,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
        signingKey: options.signingKey,
      },
      this.ctx
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
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
    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({
      unprotectedHeaders: new Map([[Header.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.privateKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.privateKey.keyId)
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceMac = await DeviceMac.create(
      {
        unprotectedHeaders,
        protectedHeaders,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
        privateKey: options.privateKey,
        ephemeralKey: options.publicKey,
        sessionTranscript: options.sessionTranscript,
      },
      this.ctx
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
        deviceMac,
      }),
    })
  }
}
