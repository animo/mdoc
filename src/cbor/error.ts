// biome-ignore format:
class CborError extends Error { constructor(message: string = new.target.name) { super(message) } }

export class CborDecodeError extends CborError {}
export class CborEncodeError extends CborError {}
