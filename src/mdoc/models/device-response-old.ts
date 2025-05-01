import type { JWK } from 'jose'
import { DataItem, cborEncode } from '../../cbor/index.js'
import type { MdocContext } from '../../context.js'
import { Header, MacAlgorithm, SignatureAlgorithm } from '../../cose/headers/defaults.js'
import { ProtectedHeaders } from '../../cose/headers/protected-headers.js'
import { UnprotectedHeaders } from '../../cose/headers/unprotected-headers.js'
import { CoseKey } from '../../cose/key/key.js'
import { Mac0 } from '../../cose/mac0.js'
import { Sign1 } from '../../cose/sign1.js'
import { stringToBytes } from '../../utils/transformers.js'
import type { IssuerSignedItem } from '../issuer-signed-item.js'
import { parseDeviceResponse } from '../parser.js'
import { calculateDeviceAutenticationBytes } from '../utils.js'
import type { DeviceRequestOld, DocRequestOld } from './device-request-old.js'
import { DeviceSignedDocument } from './device-signed-document.js'
import type { IssuerSignedDocument } from './issuer-signed-document.js'
import { MDocOld } from './mdoc.js'
import {
  findMdocMatchingDocType,
  limitDisclosureToDeviceRequestNameSpaces,
  limitDisclosureToInputDescriptor,
} from './pex-limit-disclosure.js'
import type { InputDescriptor, PresentationDefinition } from './presentation-definition.js'
import type { DeviceAuthOld, DeviceSignedOld, MacSupportedAlgs, SupportedAlgs } from './types.js'

type SessionTranscriptCallback = (context: {
  crypto: MdocContext['crypto']
}) => Promise<Uint8Array>

/**
 * A builder class for creating a device response.
 */
export class DeviceResponseOld {
  private mdoc: MDocOld
  private pd?: PresentationDefinition
  private deviceRequest?: DeviceRequestOld
  private sessionTranscriptBytes?: Uint8Array
  private sessionTranscriptCallback?: SessionTranscriptCallback
  private useMac = true
  private devicePrivateKey?: JWK
  public nameSpaces: Map<string, Map<string, unknown>> = new Map()
  private alg?: SupportedAlgs
  private macAlg?: MacSupportedAlgs
  private ephemeralPublicKey?: JWK

  public static from(mdoc: MDocOld | Uint8Array): DeviceResponseOld {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponseOld(parseDeviceResponse(mdoc))
    }
    return new DeviceResponseOld(mdoc)
  }

  constructor(mdoc: MDocOld) {
    this.mdoc = mdoc
  }

  public usingPresentationDefinition(pd: PresentationDefinition): DeviceResponseOld {
    if (!pd.input_descriptors.length) {
      throw new Error('The Presentation Definition must have at least one Input Descriptor object.')
    }

    const hasDuplicates = pd.input_descriptors.some(
      (id1, idx) => pd.input_descriptors.findIndex((id2) => id2.id === id1.id) !== idx
    )
    if (hasDuplicates) {
      throw new Error('Each Input Descriptor object must have a unique id property.')
    }

    this.pd = pd
    return this
  }

  public usingDeviceRequest(deviceRequest: DeviceRequestOld): DeviceResponseOld {
    if (!deviceRequest.docRequests.length) {
      throw new Error('The deviceRequest must have at least one docRequest object.')
    }

    this.deviceRequest = deviceRequest
    return this
  }

  public usingSessionTranscriptBytes(sessionTranscriptBytes: Uint8Array): DeviceResponseOld {
    if (this.sessionTranscriptBytes || this.sessionTranscriptCallback) {
      throw new Error(
        'A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      )
    }
    this.sessionTranscriptBytes = sessionTranscriptBytes
    return this
  }

  private usingSessionTranscriptCallback(sessionTranscriptCallback: SessionTranscriptCallback): DeviceResponseOld {
    if (this.sessionTranscriptBytes || this.sessionTranscriptCallback) {
      throw new Error(
        'A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      )
    }

    this.sessionTranscriptCallback = sessionTranscriptCallback
    return this
  }

  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex B (OID4VP), 2024 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   */
  public usingSessionTranscriptForOID4VP(input: {
    mdocGeneratedNonce: string
    clientId: string
    responseUri: string
    verifierGeneratedNonce: string
  }): DeviceResponseOld {
    this.usingSessionTranscriptCallback((context) =>
      DeviceResponseOld.calculateSessionTranscriptBytesForOID4VP({ ...input, context })
    )
    return this
  }

  public static async calculateSessionTranscriptBytesForOID4VP(input: {
    context: {
      crypto: MdocContext['crypto']
    }
    mdocGeneratedNonce: string
    clientId: string
    responseUri: string
    verifierGeneratedNonce: string
  }) {
    const { mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce, context } = input

    return cborEncode(
      DataItem.fromData([
        null, // deviceEngagementBytes
        null, // eReaderKeyBytes
        [
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([clientId, mdocGeneratedNonce]),
          }),
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([responseUri, mdocGeneratedNonce]),
          }),
          verifierGeneratedNonce,
        ],
      ])
    )
  }

  public static async calculateSessionTranscriptBytesForOID4VPDCApi(input: {
    context: {
      crypto: MdocContext['crypto']
    }
    clientId: string
    origin: string
    verifierGeneratedNonce: string
  }) {
    const { clientId, verifierGeneratedNonce, context, origin } = input

    return cborEncode(
      DataItem.fromData([
        null, // deviceEngagementBytes
        null, // eReaderKeyBytes
        [
          'OpenID4VPDCAPIHandover', //  A fixed identifier for this handover type
          await context.crypto.digest({
            digestAlgorithm: 'SHA-256',
            bytes: cborEncode([origin, clientId, verifierGeneratedNonce]),
          }),
        ],
      ])
    )
  }

  /**
   * Set the session transcript data to use for the device response as defined in [OID4VP B.3.4.1, Draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.3.4.1)
   *
   * This should match the session transcript as it will be calculated by the verifier.
   */
  public usingSessionTranscriptForForOID4VPDCApi(input: {
    origin: string
    clientId: string
    verifierGeneratedNonce: string
  }): DeviceResponseOld {
    this.usingSessionTranscriptCallback((context) =>
      DeviceResponseOld.calculateSessionTranscriptBytesForOID4VPDCApi({ ...input, context })
    )
    return this
  }

  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex A (Web API), 2024 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   */
  public usingSessionTranscriptForWebAPI(input: {
    deviceEngagementBytes: Uint8Array
    readerEngagementBytes: Uint8Array
    eReaderKeyBytes: Uint8Array
  }): DeviceResponseOld {
    this.usingSessionTranscriptCallback((context) =>
      DeviceResponseOld.calculateSessionTranscriptBytesForWebApi({ ...input, context })
    )
    return this
  }

  public static async calculateSessionTranscriptBytesForWebApi(input: {
    context: {
      crypto: MdocContext['crypto']
    }
    deviceEngagementBytes: Uint8Array
    readerEngagementBytes: Uint8Array
    eReaderKeyBytes: Uint8Array
  }) {
    const { deviceEngagementBytes, eReaderKeyBytes, readerEngagementBytes, context } = input

    const readerEngagementBytesHash = await context.crypto.digest({
      bytes: readerEngagementBytes,
      digestAlgorithm: 'SHA-256',
    })

    return cborEncode(
      DataItem.fromData([
        new DataItem({ buffer: deviceEngagementBytes }),
        new DataItem({ buffer: eReaderKeyBytes }),
        readerEngagementBytesHash,
      ])
    )
  }

  /**
   * Add a namespace to the device response.
   */
  public addDeviceNameSpace(
    nameSpace: string,
    data: Map<string, unknown> | Record<string, unknown>
  ): DeviceResponseOld {
    this.nameSpaces.set(nameSpace, data instanceof Map ? data : new Map(Object.entries(data)))
    return this
  }

  /**
   * Set the device's private key to be used for signing the device response.
   */
  public authenticateWithSignature(devicePrivateKey: JWK, alg: SupportedAlgs): DeviceResponseOld {
    this.devicePrivateKey = devicePrivateKey
    this.alg = alg
    this.useMac = false
    return this
  }

  /**
   * Set the reader shared key to be used for signing the device response with MAC.
   */
  public authenticateWithMAC(devicePrivateKey: JWK, ephemeralPublicKey: JWK, alg: MacSupportedAlgs): DeviceResponseOld {
    this.devicePrivateKey = devicePrivateKey
    this.ephemeralPublicKey = ephemeralPublicKey
    this.macAlg = alg
    this.useMac = true
    return this
  }

  /**
   * Sign the device response and return the MDoc.
   */
  public async sign(ctx: {
    crypto: MdocContext['crypto']
    cose: MdocContext['cose']
  }): Promise<MDocOld> {
    const requests = this.pd?.input_descriptors ?? this.deviceRequest?.docRequests
    if (!requests) {
      throw new Error(
        'Must provide a presentation definition or device request with .usingPresentationDefinition() or .usingDeviceRequest()'
      )
    }

    // Calculate session transcript bytes if not calculated previously yet
    if (!this.sessionTranscriptBytes && this.sessionTranscriptCallback) {
      this.sessionTranscriptBytes = await this.sessionTranscriptCallback(ctx)
      this.sessionTranscriptCallback = undefined
    }

    const sessionTranscriptBytes = this.sessionTranscriptBytes
    if (!sessionTranscriptBytes) {
      throw new Error(
        'Must provide the session transcript with either .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      )
    }

    const limitedDeviceSignedDocuments = await Promise.all(
      requests.map(async (request) => {
        const isDeviceRequest = (r: InputDescriptor | DocRequestOld): r is DocRequestOld => 'itemsRequest' in request

        let mdoc: IssuerSignedDocument
        let disclosedNameSpaces: Map<string, IssuerSignedItem[]>
        if (isDeviceRequest(request)) {
          const docType = request.itemsRequest.data.docType
          mdoc = findMdocMatchingDocType(this.mdoc, docType)
          disclosedNameSpaces = limitDisclosureToDeviceRequestNameSpaces(mdoc, request.itemsRequest.data.nameSpaces)
        } else {
          mdoc = findMdocMatchingDocType(this.mdoc, request.id)
          disclosedNameSpaces = limitDisclosureToInputDescriptor(mdoc, request)
        }

        return new DeviceSignedDocument(
          mdoc.docType,
          {
            nameSpaces: disclosedNameSpaces,
            issuerAuth: mdoc.issuerSigned.issuerAuth,
          },
          await this.getDeviceSigned(mdoc.docType, sessionTranscriptBytes, ctx)
        )
      })
    )

    return new MDocOld(limitedDeviceSignedDocuments)
  }

  private async getDeviceSigned(
    docType: string,
    sessionTranscriptBytes: Uint8Array,
    ctx: {
      cose: MdocContext['cose']
      crypto: MdocContext['crypto']
    }
  ): Promise<DeviceSignedOld> {
    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      sessionTranscriptBytes,
      docType,
      this.nameSpaces
    )

    let deviceAuth: DeviceAuthOld
    if (this.useMac) {
      deviceAuth = await this.getDeviceAuthMac(deviceAuthenticationBytes, sessionTranscriptBytes, ctx)
    } else {
      deviceAuth = await this.getDeviceAuthSign(deviceAuthenticationBytes, ctx)
    }

    const deviceSigned: DeviceSignedOld = {
      nameSpaces: this.nameSpaces,
      deviceAuth,
    }

    return deviceSigned
  }

  private async getDeviceAuthMac(
    deviceAuthenticationBytes: Uint8Array,
    sessionTranscriptBytes: Uint8Array,
    ctx: {
      cose: Pick<MdocContext['cose'], 'mac0'>
      crypto: MdocContext['crypto']
    }
  ): Promise<DeviceAuthOld> {
    if (!this.devicePrivateKey) {
      throw new Error('Missing devicePrivateKey for getDeviceAuthMac')
    }

    if (!this.ephemeralPublicKey) {
      throw new Error('Missing ephemeralPublicKey for getDeviceAuthMac')
    }

    const { kid } = this.devicePrivateKey
    const ephemeralMacKeyJwk = await ctx.crypto.calculateEphemeralMacKeyJwk({
      privateKey: COSEKeyToRAW(CoseKey.fromJWK(this.devicePrivateKey).encode()),
      publicKey: COSEKeyToRAW(CoseKey.fromJWK(this.ephemeralPublicKey).encode()),

      sessionTranscriptBytes: sessionTranscriptBytes,
    })

    if (!this.macAlg) throw new Error('Missing macAlg')

    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, MacAlgorithm[this.macAlg]]]),
    })

    const unprotectedHeaders = kid
      ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyID, stringToBytes(kid)]]) })
      : undefined

    const mac0 = new Mac0({ protectedHeaders, unprotectedHeaders, detachedContent: deviceAuthenticationBytes })

    const tag = await ctx.cose.mac0.sign({ mac0, jwk: ephemeralMacKeyJwk })
    mac0.tag = tag
    return { deviceMac: mac0 }
  }

  private async getDeviceAuthSign(
    detachedContent: Uint8Array,
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<DeviceAuthOld> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey')

    if (!this.alg) {
      throw new Error('The alg header must be set.')
    }

    const { kid } = this.devicePrivateKey
    const unprotectedHeaders = kid
      ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyID, stringToBytes(kid)]]) })
      : undefined
    const protectedHeaders = new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, SignatureAlgorithm[this.alg]]]),
    })

    const sign1 = new Sign1({
      protectedHeaders,
      unprotectedHeaders,
      detachedContent,
    })

    const signature = await ctx.cose.sign1.sign({
      sign1,
      jwk: this.devicePrivateKey,
    })

    sign1.signature = signature

    return { deviceSignature: sign1 }
  }
}
