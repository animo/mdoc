import { DuplicateDocumentInDeviceResponseError } from '../errors'
import type { Document } from '../models'

export class DeviceResponseBuilder {
  public documents: Array<Document> = []

  private addDocument(document: Document) {
    const duplicateDocument = this.documents.find((doc) => doc.docType === document.docType)

    if (duplicateDocument) {
      throw new DuplicateDocumentInDeviceResponseError()
    }

    this.documents.push(document)
  }
}
