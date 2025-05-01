export interface PresentationDefinitionField {
  path: string[]
  intent_to_retain: boolean
  optional?: boolean
}

export interface Format {
  mso_mdoc: {
    alg: string[]
  }
}

export interface InputDescriptor {
  id: string
  format: Format
  constraints: {
    limit_disclosure: string
    fields: PresentationDefinitionField[]
  }
}

export interface PresentationDefinition {
  id: string
  input_descriptors: InputDescriptor[]
}
