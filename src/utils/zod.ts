import z from 'zod'

export const zUint8Array = z.instanceof<typeof Uint8Array<ArrayBufferLike>>(Uint8Array)
