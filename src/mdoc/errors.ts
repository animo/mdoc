// biome-ignore format:
export class MdlError extends Error { constructor(message: string = new.target.name) { super(message) } }

export class MdlParseError extends MdlError {}
