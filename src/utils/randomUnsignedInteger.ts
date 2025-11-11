import type { MdocContext } from '../context'

export const randomUnsignedInteger = (ctx: Pick<MdocContext, 'crypto'>) => {
  const bytes = ctx.crypto.random(4)
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0
}
