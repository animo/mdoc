import type { JWK } from 'jose'
import type { Mac0 } from '../../cose/mac0.js'
import type { Sign1 } from '../../cose/sign1.js'
import type { IssuerSignedDataItem, IssuerSignedItem } from '../issuer-signed-item.js'
import type { IssuerAuth } from './issuer-auth.js'

export interface ValidityInfoOld {
  signed: Date
  validFrom: Date
  validUntil: Date
  expectedUpdate?: Date
}

export type IssuerNameSpaces = Map<string, IssuerSignedItem[]>

export type MdocNameSpaces = Map<string, Map<string, unknown>>

export interface IssuerSignedOld {
  issuerAuth: IssuerAuth
  nameSpaces: IssuerNameSpaces
}

export type DeviceAuthOld =
  | ({ deviceMac: Mac0 } & { deviceSignature?: never })
  | ({ deviceMac?: never } & { deviceSignature: Sign1 })

export interface DeviceSignedOld {
  deviceAuth: DeviceAuthOld
  nameSpaces: Map<string, Map<string, unknown>>
}

export type RawIndexedDataItem = IssuerSignedDataItem[]

export type RawNameSpaces = Map<string, RawIndexedDataItem>

type RawAuthElement = ConstructorParameters<typeof Sign1>

export type RawIssuerAuth = ConstructorParameters<typeof Sign1>

export type RawDeviceAuth = Map<'deviceMac' | 'deviceSignature', RawAuthElement>

export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512'

export interface DiagnosticInformation {
  general: {
    type: string
    version: string
    status: number
    documents: number
  }
  validityInfo: ValidityInfoOld
  attributes: {
    ns: string
    id: string
    value: unknown
    isValid: boolean
    matchCertificate?: boolean
  }[]
  deviceAttributes: {
    ns: string
    id: string
    value: unknown
  }[]
  issuerCertificate?: {
    subjectName: string
    notBefore: Date
    notAfter: Date
    serialNumber: string
    thumbprint: string
    pem: string
  }
  issuerSignature: {
    alg: string
    isValid: boolean
    reasons?: string[]
    digests: Record<string, number>
  }
  deviceKey: {
    jwk: JWK
  }
  deviceSignature: {
    alg: string
    isValid: boolean
    reasons?: string[]
  }
  dataIntegrity: {
    disclosedAttributes: string
    isValid: boolean
    reasons?: string[]
  }
}

export interface DeviceKeyInfoOld {
  deviceKey: Map<number, number | Uint8Array>
  [key: string]: unknown
}

export interface MSO {
  digestAlgorithm: DigestAlgorithm
  docType: string
  version: string

  validityInfo: ValidityInfoOld

  valueDigests?: Map<string, Map<number, Uint8Array>>

  validityDigests?: Record<string, Map<number, Uint8Array>>

  deviceKeyInfo?: DeviceKeyInfoOld
}

export type DocTypeOld = 'org.iso.18013.5.1.mDL' | (string & {})

export type SupportedAlgs = 'ES256' | 'ES384' | 'ES512' | 'EdDSA'

export type MacSupportedAlgs = 'HS256'
