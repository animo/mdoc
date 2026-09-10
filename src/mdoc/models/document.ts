import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceSigned, type DeviceSignedEncodedStructure } from './device-signed'
import type { DocType } from './doctype'
import { Errors, type ErrorsEncodedStructure } from './errors'
import { IssuerSigned, type IssuerSignedEncodedStructure } from './issuer-signed'
import type { Namespace } from './namespace'

const documentSchema = typedMap([
  ['docType', z.string()],
  ['issuerSigned', z.instanceof(IssuerSigned)],
  ['deviceSigned', z.instanceof(DeviceSigned)],
  ['errors', z.instanceof(Errors).exactOptional()],
] as const)

export type DocumentDecodedStructure = z.output<typeof documentSchema>
export type DocumentEncodedStructure = z.input<typeof documentSchema>

export type DocumentOptions = {
  docType: DocType
  issuerSigned: IssuerSigned
  deviceSigned: DeviceSigned
  errors?: Errors
}

export class Document extends CborStructure<DocumentEncodedStructure, DocumentDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(documentSchema.in, documentSchema.out, {
      decode: (input) => {
        const map: DocumentDecodedStructure = TypedMap.fromMap(input)

        map.set(
          'issuerSigned',
          IssuerSigned.fromEncodedStructure(input.get('issuerSigned') as IssuerSignedEncodedStructure)
        )
        map.set(
          'deviceSigned',
          DeviceSigned.fromEncodedStructure(input.get('deviceSigned') as DeviceSignedEncodedStructure)
        )

        if (input.has('errors')) {
          map.set('errors', Errors.fromEncodedStructure(input.get('errors') as ErrorsEncodedStructure))
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('issuerSigned', output.get('issuerSigned').encodedStructure)
        map.set('deviceSigned', output.get('deviceSigned').encodedStructure)

        const errors = output.get('errors')
        if (errors) {
          map.set('errors', errors.encodedStructure)
        }

        return map
      },
    })
  }

  public get docType() {
    return this.structure.get('docType')
  }

  public get issuerSigned() {
    return this.structure.get('issuerSigned')
  }

  public get deviceSigned() {
    return this.structure.get('deviceSigned')
  }

  public get errors() {
    return this.structure.get('errors')
  }

  public getIssuerNamespace(namespace: Namespace) {
    const issuerSigned = this.structure.get('issuerSigned')
    const issuerNamespaces = issuerSigned?.issuerNamespaces?.issuerNamespaces

    if (!issuerNamespaces) {
      return undefined
    }

    return issuerNamespaces.get(namespace)
  }

  public static create(options: DocumentOptions): Document {
    const map: DocumentDecodedStructure = new TypedMap([
      ['docType', options.docType],
      ['issuerSigned', options.issuerSigned],
      ['deviceSigned', options.deviceSigned],
    ])
    if (options.errors) {
      map.set('errors', options.errors)
    }
    return this.fromDecodedStructure(map)
  }
}
