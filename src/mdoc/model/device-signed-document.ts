import { DataItem } from '../../cbor/data-item.js'
import { IssuerSignedDocument } from './issuer-signed-document.js'
import type { DeviceSigned, DocType, IssuerSigned, MdocNameSpaces } from './types.js'

/**
 * Represents a device signed document.
 *
 * Note: You don't need to instantiate this class.
 * This is the return type of the parser and it will be generated by the DeviceResponse builder.
 */
export class DeviceSignedDocument extends IssuerSignedDocument {
  constructor(
    docType: DocType,
    issuerSigned: IssuerSigned,
    public readonly deviceSigned: DeviceSigned
  ) {
    super(docType, issuerSigned)
  }

  override prepare(): Map<string, unknown> {
    const doc = super.prepare()

    const deviceSignature: Array<unknown> | undefined =
      this.deviceSigned.deviceAuth.deviceSignature?.getContentForEncoding()
    const deviceMac: Array<unknown> | undefined = this.deviceSigned.deviceAuth.deviceMac?.getContentForEncoding()
    // detach payload
    if (deviceMac) {
      deviceMac[2] = null
    }
    if (deviceSignature) {
      deviceSignature[2] = null
    }
    //
    doc.set('deviceSigned', {
      ...this.deviceSigned,
      nameSpaces: DataItem.fromData(this.deviceSigned.nameSpaces),
      // TODO: ERRORS MISSING
      deviceAuth: {
        ...this.deviceSigned.deviceAuth,
        // This is to prevent an undfeined value from ending up in the device signed structure
        ...(deviceSignature ? { deviceSignature } : {}),
        ...(deviceMac ? { deviceMac } : {}),
      },
    })

    return doc
  }

  /**
   * Helper method to get the values in a namespace as a JS object.
   *
   * @param {string} namespace - The namespace to add.
   * @returns {Map<string, unknown>} - The values in the namespace as an object
   */
  getDeviceNameSpace(namespace: string): Map<string, unknown> | undefined {
    return this.deviceSigned.nameSpaces.get(namespace)
  }

  /**
   * List of namespaces in the document.
   */
  get deviceSignedNameSpaces(): string[] {
    return Array.from(this.deviceSigned.nameSpaces.keys())
  }

  public get allDeviceSignedNamespaces(): MdocNameSpaces {
    const namespaces = this.deviceSignedNameSpaces

    return new Map(
      namespaces.map((namespace) => {
        const namespaceValues = this.getDeviceNameSpace(namespace)
        if (!namespaceValues) {
          throw new Error(`Cannot extract the namespace '${namespace}' from the mdoc.`)
        }
        return [namespace, namespaceValues]
      })
    )
  }
}
