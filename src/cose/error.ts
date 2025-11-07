// biome-ignore format: no explanation
class CoseError extends Error {
  constructor(message: string = new.target.name) {
    super(message)
  }
}

export class CoseUnsupportedMacError extends CoseError {}
export class CoseInvalidSignatureError extends CoseError {}
export class CoseInvalidAlgorithmError extends CoseError {}
export class CosePayloadMustBeNullError extends CoseError {}
export class CosePayloadMustBeDefinedError extends CoseError {}
export class CosePayloadInvalidStructureError extends CoseError {}
export class CoseInvalidTypeForKeyError extends CoseError {}
export class CoseInvalidValueForKtyError extends CoseError {}
export class CoseInvalidKtyForRawError extends CoseError {}
export class CoseXNotDefinedError extends CoseError {}
export class CoseYNotDefinedError extends CoseError {}
export class CoseDNotDefinedError extends CoseError {}
export class CoseKNotDefinedError extends CoseError {}
export class CoseEphemeralMacKeyIsRequiredError extends CoseError {}
export class CoseCertificateNotFoundError extends CoseError {}
export class CoseKeyTypeNotSupportedForPrivateKeyExtractionError extends CoseError {}
