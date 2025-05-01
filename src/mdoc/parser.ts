import { compareVersions } from 'compare-versions'
import { cborDecode } from '../cbor/index.js'
import { Mac0 } from '../cose/mac0.js'
import { Sign1 } from '../cose/sign1.js'
import { MdlParseError } from './errors.js'
import { IssuerSignedItem } from './issuer-signed-item.js'
import { DeviceSignedDocument } from './models/device-signed-document.js'
import { IssuerAuth } from './models/issuer-auth.js'
import { IssuerSignedDocument } from './models/issuer-signed-document.js'
import { MDocOld } from './models/mdoc.js'
import type {
  DeviceAuthOld,
  DeviceSignedOld,
  IssuerNameSpaces,
  IssuerSignedOld,
  RawDeviceAuth,
  RawIndexedDataItem,
  RawIssuerAuth,
  RawNameSpaces,
} from './models/types.js'

const parseIssuerAuthElement = (rawIssuerAuth: RawIssuerAuth, expectedDocType?: string): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth)
  const { docType, version } = issuerAuth.mobileSecurityObject

  if (expectedDocType && docType !== expectedDocType) {
    throw new MdlParseError(`The issuerAuth docType must be ${expectedDocType}`)
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MdlParseError("The issuerAuth version must be '1.0'")
  }

  return issuerAuth
}

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuthOld => {
  const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth)
  if (deviceSignature) {
    return { deviceSignature: new Sign1(...deviceSignature) }
  }
  if (deviceMac) {
    return { deviceMac: new Mac0(...deviceMac) }
  }

  throw new MdlParseError(`Invalid deviceAuth element. Missing 'deviceSignature' and 'deviceMac'`)
}

const namespaceToArray = (entries: RawIndexedDataItem): IssuerSignedItem[] =>
  entries.map((di) => new IssuerSignedItem(di))

const mapIssuerNameSpaces = (namespace: RawNameSpaces): IssuerNameSpaces =>
  new Map(Array.from(namespace.entries()).map(([nameSpace, entries]) => [nameSpace, namespaceToArray(entries)]))

export const parseIssuerSigned = (
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): IssuerSignedDocument => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let issuerSignedDecoded: Map<string, any>
  try {
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    issuerSignedDecoded = issuerSigned instanceof Map ? issuerSigned : (cborDecode(issuerSigned) as Map<string, any>)
  } catch (err) {
    throw new MdlParseError(
      `Unable to decode issuer signed document: ${err instanceof Error ? err.message : 'Unknown error'}`
    )
  }

  const issuerAuth = parseIssuerAuthElement(issuerSignedDecoded.get('issuerAuth'), expectedDocType)

  const parsedIssuerSigned: IssuerSignedOld = {
    ...issuerSignedDecoded,
    nameSpaces: mapIssuerNameSpaces(issuerSignedDecoded.get('nameSpaces')),
    issuerAuth,
  }

  return new IssuerSignedDocument(issuerAuth.mobileSecurityObject.docType, parsedIssuerSigned)
}

export const parseDeviceSigned = (
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  deviceSigned: Uint8Array | Map<string, any>,
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): DeviceSignedDocument => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let deviceSignedDecoded: Map<string, any>
  try {
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    deviceSignedDecoded = deviceSigned instanceof Map ? deviceSigned : (cborDecode(deviceSigned) as Map<string, any>)
  } catch (err) {
    throw new MdlParseError(
      `Unable to decode device signed document : ${err instanceof Error ? err.message : 'Unknown error'}`
    )
  }

  const deviceSignedParsed: DeviceSignedOld = {
    ...deviceSignedDecoded,
    nameSpaces: deviceSignedDecoded.get('nameSpaces').data,
    deviceAuth: parseDeviceAuthElement(deviceSignedDecoded.get('deviceAuth')),
  }

  const issuerSignedDocument = parseIssuerSigned(issuerSigned, expectedDocType)

  return new DeviceSignedDocument(issuerSignedDocument.docType, issuerSignedDocument.issuerSigned, deviceSignedParsed)
}

export const parseDeviceResponse = (encoded: Uint8Array): MDocOld => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let deviceResponse: Map<string, any>
  try {
    deviceResponse = cborDecode(encoded) as Map<string, unknown>
  } catch (err) {
    throw new MdlParseError(`Unable to decode device response: ${err instanceof Error ? err.message : 'Unknown error'}`)
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse)

  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  const parsedDocuments: IssuerSignedDocument[] = documents.map((doc: Map<string, any>): IssuerSignedDocument => {
    const docType = doc.get('docType')
    const issuerSigned = doc.get('issuerSigned')
    const deviceSigned = doc.get('deviceSigned')

    if (deviceSigned) {
      return parseDeviceSigned(deviceSigned, issuerSigned, docType)
    }
    return parseIssuerSigned(issuerSigned, docType)
  })

  return new MDocOld(parsedDocuments, version, status)
}
