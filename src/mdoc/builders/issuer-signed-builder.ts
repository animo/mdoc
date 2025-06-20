import type { MdocContext } from '../../context'
import {
  type CoseKey,
  type DigestAlgorithm,
  Header,
  ProtectedHeaders,
  type SignatureAlgorithm,
  UnprotectedHeaders,
} from '../../cose'
import { DuplicateNamespaceInIssuerNamespacesError } from '../errors'
import {
  DeviceKeyInfo,
  type DeviceKeyInfoOptions,
  type Digest,
  type DigestId,
  type DocType,
  IssuerAuth,
  IssuerNamespace,
  IssuerSigned,
  IssuerSignedItem,
  MobileSecurityObject,
  type MobileSecurityObjectOptions,
  type Namespace,
  StatusInfo,
  type StatusInfoStructure,
  ValidityInfo,
  type ValidityInfoOptions,
  ValueDigests,
} from '../models'

export class IssuerSignedBuilder {
  private docType: DocType
  private namespaces: IssuerNamespace
  private ctx: Pick<MdocContext, 'cose' | 'crypto'>

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.docType = docType
    this.ctx = ctx
    this.namespaces = new IssuerNamespace({ issuerNamespaces: new Map() })
  }

  public addIssuerNamespace(namespace: Namespace, value: Record<string | number, unknown>) {
    const issuerNamespace = this.namespaces.issuerNamespaces.get(namespace) ?? []

    const issuerSignedItems = Object.entries(value).map(
      ([k, v]) =>
        new IssuerSignedItem({
          digestId: issuerNamespace.length,
          elementIdentifier: k,
          elementValue: v,
          random: this.ctx.crypto.random(32),
        })
    )

    issuerNamespace.push(...issuerSignedItems)

    this.namespaces.issuerNamespaces.set(namespace, issuerNamespace)

    return this
  }

  private async convertIssuerNamespacesIntoValueDigests(digestAlgorithm: DigestAlgorithm): Promise<ValueDigests> {
    const valueDigests = new Map<Namespace, Map<DigestId, Digest>>()

    for (const [namespace, issuerSignedItems] of this.namespaces.issuerNamespaces) {
      if (valueDigests.has(namespace)) {
        throw new DuplicateNamespaceInIssuerNamespacesError()
      }

      const digests = new Map<DigestId, Digest>()
      for (const issuerSignedItem of issuerSignedItems) {
        const digest = await this.ctx.crypto.digest({
          digestAlgorithm,
          bytes: issuerSignedItem.encode({ asDataItem: true }),
        })

        digests.set(issuerSignedItem.digestId, digest)
      }
      valueDigests.set(namespace, digests)
    }

    return new ValueDigests({ valueDigests })
  }

  public async sign(options: {
    signingKey: CoseKey
    algorithm: SignatureAlgorithm
    digestAlgorithm: DigestAlgorithm
    validityInfo: ValidityInfo | ValidityInfoOptions
    deviceKeyInfo: DeviceKeyInfo | DeviceKeyInfoOptions
    certificate: Uint8Array
    statusList?: StatusInfoStructure
  }): Promise<IssuerSigned> {
    const validityInfo =
      options.validityInfo instanceof ValidityInfo ? options.validityInfo : new ValidityInfo(options.validityInfo)

    const deviceKeyInfo =
      options.deviceKeyInfo instanceof DeviceKeyInfo ? options.deviceKeyInfo : new DeviceKeyInfo(options.deviceKeyInfo)

    const payload: MobileSecurityObjectOptions = {
      docType: this.docType,
      validityInfo,
      digestAlgorithm: options.digestAlgorithm,
      deviceKeyInfo,
      valueDigests: await this.convertIssuerNamespacesIntoValueDigests(options.digestAlgorithm),
    }
    if (options.statusList) {
      payload.status = new StatusInfo({ key: options.signingKey, statusList: options.statusList })
    }
    const mso = new MobileSecurityObject(payload)

    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = new UnprotectedHeaders({
      unprotectedHeaders: new Map([[Header.X5Chain, options.certificate]]),
    })

    if (options.signingKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.signingKey.keyId)
    }

    const issuerAuth = new IssuerAuth({
      payload: mso.encode({ asDataItem: true }),
      unprotectedHeaders,
      protectedHeaders,
    })

    await issuerAuth.addSignature(
      {
        signingKey: options.signingKey,
      },
      this.ctx
    )

    return new IssuerSigned({
      issuerNamespaces: this.namespaces,
      issuerAuth,
    })
  }
}
