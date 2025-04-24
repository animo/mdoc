// biome-ignore format:
class CoseError extends Error { constructor(message: string = new.target.name) { super(message) } }

export class CoseUnsupportedMac extends CoseError {}
export class CoseInvalidSignature extends CoseError {}
export class CoseInvalidAlgorithm extends CoseError {}
export class CosePayloadMustBeNull extends CoseError {}
export class CosePayloadMustBeDefined extends CoseError {}
export class CoseInvalidTypeForKey extends CoseError {}
export class CoseInvalidValueForKty extends CoseError {}
