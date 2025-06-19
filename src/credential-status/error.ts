// biome-ignore format:
class StatusListError extends Error { constructor(message: string = new.target.name) { super(message) } }

export class InvalidStatusListFormatError extends StatusListError {}
export class InvalidStatusListBitsError extends StatusListError {
  constructor(bits: number, allowedBits: readonly number[]) {
    super(`Invalid bits per entry: ${bits}. Allowed values are ${allowedBits.join(', ')}.`)
  }
}
